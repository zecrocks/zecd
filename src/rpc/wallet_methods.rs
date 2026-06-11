//! Wallet RPCs mapped onto Orchard shielded operations.

use std::collections::{BTreeSet, HashMap};

use serde_json::{json, Map, Value};
use zcash_protocol::TxId;
use zip321::{Payment, TransactionRequest};

use crate::amount::{signed_zats_to_value, value_to_zats, zats_to_value};
use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::store::Passphrase;
use crate::wallet::{labels, read, SyncStatus};

fn opt_str(req: &RpcRequest, i: usize) -> Option<String> {
    req.param(i).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Parse a display-hex txid (reversed) into a [`TxId`] (internal byte order).
fn parse_txid(display_hex: &str) -> Option<TxId> {
    let mut bytes = hex::decode(display_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    bytes.reverse();
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(TxId::from_bytes(arr))
}

pub fn listwallets(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(state.registry.names()))
}

pub async fn getnewaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = opt_str(req, 0).filter(|s| !s.is_empty());
    // Param 1 (address_type): every zecd address is an Orchard unified address. Accept the
    // matching names but reject Bitcoin types, so a caller asking for e.g. "bech32" isn't
    // silently handed a different kind of address than it asked for.
    if let Some(t) = opt_str(req, 1).filter(|s| !s.is_empty()) {
        if !t.eq_ignore_ascii_case("orchard") && !t.eq_ignore_ascii_case("unified") {
            return Err(RpcError::invalid_address_or_key(format!(
                "Unknown address type '{t}'"
            )));
        }
    }
    let handle = state.registry.get(wallet)?.clone();
    let addr = handle.get_new_address(label).await?;
    Ok(Value::String(addr))
}

pub fn getbalance(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir)?;
    Ok(zats_to_value(info.total_spendable))
}

pub fn getunconfirmedbalance(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir)?;
    Ok(zats_to_value(info.pending))
}

/// `getbalances` - the modern (Bitcoin Core 0.19+) balance triple. There is no watch-only
/// support, so the `watchonly` object is omitted (as Bitcoin Core does for wallets without
/// watch-only funds).
pub fn getbalances(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir)?;
    let mut obj = json!({
        "mine": {
            "trusted": zats_to_value(info.total_spendable),
            "untrusted_pending": zats_to_value(info.pending),
            "immature": zats_to_value(info.immature),
        },
    });
    // `lastprocessedblock` (Bitcoin Core 26+): the block the balances are anchored to -
    // for zecd that is the fully-scanned height, the same anchor as `getblockcount`.
    if let Some(h) = handle.status().fully_scanned {
        if let Ok(Some((hash, _))) = read::block_info_at(&handle.dir, h) {
            obj["lastprocessedblock"] = json!({ "hash": hash, "height": h });
        }
    }
    Ok(obj)
}

pub fn getwalletinfo(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir)?;
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
        "balance": zats_to_value(info.total_spendable),
        "unconfirmed_balance": zats_to_value(info.pending),
        "immature_balance": zats_to_value(info.immature),
        "txcount": txcount,
        "keypoolsize": 1,
        "keypoolsize_hd_internal": 0,
        "paytxfee": zats_to_value(0),
        "private_keys_enabled": true,
        "avoid_reuse": false,
        "scanning": scanning,
        "descriptors": false
    });
    // Only present for passphrase-encrypted wallets (matches Bitcoin Core): the unix time the
    // wallet auto-relocks, or 0 if currently locked.
    if st.encrypted {
        obj["unlocked_until"] = json!(st.unlocked_until.unwrap_or(0));
    }
    Ok(obj)
}

pub fn getaddressinfo(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("getaddressinfo requires an address"))?;
    let handle = state.registry.get(wallet)?;
    let v = crate::address::validate(&handle.network, addr);
    let label = labels::get_label(&handle.dir, addr).ok().flatten();
    let ismine = v.is_valid && read::is_mine(handle.network, &handle.dir, addr);
    Ok(json!({
        "address": addr,
        "isvalid": v.is_valid,
        "ismine": ismine,
        "iswatchonly": false,
        "isscript": false,
        "labels": label.map(|l| vec![l]).unwrap_or_default(),
    }))
}

pub fn setlabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("setlabel requires an address"))?;
    let label = opt_str(req, 1).unwrap_or_default();
    let handle = state.registry.get(wallet)?;
    if !crate::address::validate(&handle.network, addr).is_valid {
        return Err(RpcError::invalid_address_or_key(format!(
            "Invalid Zcash address: {addr}"
        )));
    }
    labels::set_label(&handle.dir, addr, &label)
        .map_err(|e| RpcError::database(e.to_string()))?;
    Ok(Value::Null)
}

pub fn getaddressesbylabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("getaddressesbylabel requires a label"))?;
    let handle = state.registry.get(wallet)?;
    let addrs =
        labels::addresses_for_label(&handle.dir, label).map_err(|e| RpcError::database(e.to_string()))?;
    if addrs.is_empty() {
        // Bitcoin Core: -11 RPC_WALLET_INVALID_LABEL_NAME for a label with no addresses.
        return Err(RpcError::new(
            crate::error::codes::RPC_WALLET_INVALID_LABEL_NAME,
            format!("No addresses with label {label}"),
        ));
    }
    let mut map = Map::new();
    for a in addrs {
        map.insert(a, json!({ "purpose": "receive" }));
    }
    Ok(Value::Object(map))
}

pub fn listlabels(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let all = labels::all(&handle.dir).unwrap_or_default();
    let set: BTreeSet<String> = all.into_values().collect();
    Ok(json!(set.into_iter().collect::<Vec<_>>()))
}

/// Build the per-output direction/category, skipping change and internal transfers.
fn output_category(from_account: bool, to_account: bool) -> Option<&'static str> {
    match (from_account, to_account) {
        (false, true) => Some("receive"),
        (true, false) => Some("send"),
        _ => None,
    }
}

/// Per-transaction confirmation count: -1 for an expired unmined tx (it can never confirm;
/// Bitcoin Core's "conflicted" signal, so pollers terminate), else anchored to the wallet's
/// fully-scanned height.
fn tx_confirmations(st: &SyncStatus, tx: &read::TxRecord) -> i64 {
    if tx.expired_unmined {
        -1
    } else {
        st.confirmations(tx.mined_height)
    }
}

/// Build the `listtransactions`-shaped entries for one wallet transaction: one entry per
/// non-change, non-internal output, sends negative (Bitcoin Core's sign convention).
/// `label_filter` of `Some(l)` keeps only entries labelled exactly `l`. Shared by
/// `listtransactions` and `listsinceblock`.
fn tx_entries(
    tx: &read::TxRecord,
    label_map: &HashMap<String, String>,
    confirmations: i64,
    label_filter: Option<&str>,
) -> Vec<Value> {
    let mut entries = Vec::new();
    for out in &tx.outputs {
        if out.is_change {
            continue;
        }
        let Some(category) =
            output_category(out.from_account.is_some(), out.to_account.is_some())
        else {
            continue;
        };
        let amount = if category == "send" { -out.value } else { out.value };
        let address = out.to_address.clone().unwrap_or_default();
        let label = out
            .to_address
            .as_ref()
            .and_then(|a| label_map.get(a).cloned())
            .unwrap_or_default();
        if label_filter.is_some_and(|f| f != label) {
            continue;
        }
        let mut entry = json!({
            "address": address,
            "category": category,
            "amount": signed_zats_to_value(amount),
            "label": label,
            "vout": out.output_index,
            "confirmations": confirmations,
            "txid": tx.txid_hex,
            "time": tx.block_time.unwrap_or(0),
            "timereceived": tx.block_time.unwrap_or(0),
            "bip125-replaceable": "no",
            "trusted": tx.mined_height.is_some(),
        });
        if category == "send" {
            // Bitcoin Core carries `abandoned` on send entries only.
            entry["abandoned"] = json!(tx.expired_unmined);
            if let Some(fee) = tx.fee_paid {
                entry["fee"] = signed_zats_to_value(-(fee as i64));
            }
        }
        if let Some(h) = tx.mined_height {
            entry["blockheight"] = json!(h);
        }
        entries.push(entry);
    }
    entries
}

/// Bitcoin Core's `gettransaction.amount` excludes the fee (reported separately in `fee`):
/// for a wallet-funded tx the balance delta is -(payments + fee), so add the fee back.
/// `fee_paid` is only known when the wallet funded the tx; for pure receives it is None and
/// the delta is already the received amount. A self-transfer nets to 0.
fn gettransaction_amount(account_balance_delta: i64, fee_paid: Option<u64>) -> i64 {
    account_balance_delta + fee_paid.unwrap_or(0) as i64
}

pub fn listtransactions(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // Param 0 is the label filter: "*" (or omitted/null) means all transactions; any other
    // string returns only entries carrying exactly that label (Bitcoin Core semantics).
    let label_filter = req
        .param(0)
        .and_then(|v| v.as_str())
        .filter(|s| *s != "*")
        .map(str::to_string);
    let count = match req.param(1).filter(|v| !v.is_null()) {
        None => 10,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => n as usize,
            Some(_) => return Err(RpcError::invalid_parameter("Negative count")),
            None => return Err(RpcError::type_error("count must be a number")),
        },
    };
    let skip = match req.param(2).filter(|v| !v.is_null()) {
        None => 0,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => n as usize,
            Some(_) => return Err(RpcError::invalid_parameter("Negative from")),
            None => return Err(RpcError::type_error("from must be a number")),
        },
    };
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let txs = read::list_transactions(&handle.dir)?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();

    let mut entries: Vec<Value> = Vec::new();
    for tx in &txs {
        let confirmations = tx_confirmations(&st, tx);
        entries.extend(tx_entries(tx, &label_map, confirmations, label_filter.as_deref()));
    }

    // `entries` is oldest-first; return the most recent `count` after skipping `skip`.
    let total = entries.len();
    let end = total.saturating_sub(skip);
    let start = end.saturating_sub(count);
    Ok(Value::Array(entries[start..end].to_vec()))
}

/// Aggregate wallet-received outputs (non-change, paying one of our accounts) per address,
/// counting only transactions with at least `minconf` confirmations. Returns
/// `(amount_zats, confirmations_of_most_recent_counted_tx, txids)` keyed by address.
/// Conflicted txs report -1 confirmations and so never meet `minconf >= 0`.
fn received_by_address(
    txs: &[read::TxRecord],
    st: &SyncStatus,
    minconf: i64,
) -> HashMap<String, (u64, i64, Vec<String>)> {
    let mut map: HashMap<String, (u64, i64, Vec<String>)> = HashMap::new();
    for tx in txs {
        let conf = tx_confirmations(st, tx);
        if conf < minconf {
            continue;
        }
        for out in &tx.outputs {
            if out.is_change || out.to_account.is_none() {
                continue;
            }
            let Some(addr) = &out.to_address else { continue };
            let e = map.entry(addr.clone()).or_insert((0, i64::MAX, Vec::new()));
            e.0 += out.value.max(0) as u64;
            e.1 = e.1.min(conf);
            e.2.push(tx.txid_hex.clone());
        }
    }
    map
}

/// `getreceivedbyaddress <address> [minconf]` - total received by one of the wallet's own
/// addresses, in transactions with at least `minconf` confirmations.
pub fn getreceivedbyaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("getreceivedbyaddress requires an address"))?;
    let minconf = req.param(1).and_then(|v| v.as_i64()).unwrap_or(1);
    let handle = state.registry.get(wallet)?;
    if !crate::address::validate(&handle.network, addr).is_valid {
        return Err(RpcError::invalid_address_or_key(format!(
            "Invalid Zcash address: {addr}"
        )));
    }
    if !read::is_mine(handle.network, &handle.dir, addr) {
        return Err(RpcError::wallet("Address not found in wallet"));
    }
    let st = handle.status();
    let txs = read::list_transactions(&handle.dir)?;
    let total = received_by_address(&txs, &st, minconf)
        .remove(addr)
        .map(|(amt, _, _)| amt)
        .unwrap_or(0);
    Ok(zats_to_value(total))
}

/// `listreceivedbyaddress [minconf] [include_empty] [include_watchonly] [address_filter]` -
/// per-address received totals with the txids that paid them. There is no watch-only
/// support, so `include_watchonly` is accepted and ignored.
pub fn listreceivedbyaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let minconf = req.param(0).and_then(|v| v.as_i64()).unwrap_or(1);
    let include_empty = req.param(1).and_then(|v| v.as_bool()).unwrap_or(false);
    let address_filter = req.param(3).and_then(|v| v.as_str()).map(str::to_string);
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let txs = read::list_transactions(&handle.dir)?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();
    let mut received = received_by_address(&txs, &st, minconf);

    // The address universe: everything that received, plus (with include_empty) every
    // address the wallet has ever generated.
    let mut addrs: BTreeSet<String> = received.keys().cloned().collect();
    if include_empty {
        addrs.extend(read::all_addresses(handle.network, &handle.dir));
    }

    let mut out = Vec::new();
    for addr in addrs {
        if address_filter.as_deref().is_some_and(|f| f != addr) {
            continue;
        }
        let (amount, conf, txids) = received.remove(&addr).unwrap_or((0, 0, Vec::new()));
        let conf = if txids.is_empty() { 0 } else { conf };
        out.push(json!({
            "address": addr,
            "amount": zats_to_value(amount),
            "confirmations": conf,
            "label": label_map.get(&addr).cloned().unwrap_or_default(),
            "txids": txids,
        }));
    }
    Ok(Value::Array(out))
}

/// Fold per-address received totals into per-label totals (addresses without an explicit
/// label fall under the default label `""`, like Bitcoin Core's address book). The
/// confirmation count for a label is the minimum across its addresses - Bitcoin Core's
/// `ListReceived` aggregation.
fn received_by_label(
    received: &HashMap<String, (u64, i64, Vec<String>)>,
    label_map: &HashMap<String, String>,
) -> std::collections::BTreeMap<String, (u64, i64)> {
    let mut by_label: std::collections::BTreeMap<String, (u64, i64)> = Default::default();
    for (addr, (amount, conf, _)) in received {
        let label = label_map.get(addr).cloned().unwrap_or_default();
        let e = by_label.entry(label).or_insert((0, i64::MAX));
        e.0 += amount;
        e.1 = e.1.min(*conf);
    }
    by_label
}

/// `getreceivedbylabel <label> [minconf]` - total received across the addresses carrying
/// `label`. An unknown label is `-4` like Bitcoin Core's `GetReceived`.
pub fn getreceivedbylabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("getreceivedbylabel requires a label"))?;
    let minconf = req.param(1).and_then(|v| v.as_i64()).unwrap_or(1);
    let handle = state.registry.get(wallet)?;
    let addrs = labels::addresses_for_label(&handle.dir, label)
        .map_err(|e| RpcError::database(e.to_string()))?;
    if addrs.is_empty() {
        return Err(RpcError::wallet("Label not found in wallet"));
    }
    let st = handle.status();
    let txs = read::list_transactions(&handle.dir)?;
    let received = received_by_address(&txs, &st, minconf);
    let total: u64 = addrs
        .iter()
        .filter_map(|a| received.get(a).map(|(amt, _, _)| *amt))
        .sum();
    Ok(zats_to_value(total))
}

/// `listreceivedbylabel [minconf] [include_empty] [include_watchonly]` - `listreceivedbyaddress`
/// aggregated per label. `include_watchonly` is accepted and ignored (no watch-only support).
pub fn listreceivedbylabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let minconf = req.param(0).and_then(|v| v.as_i64()).unwrap_or(1);
    let include_empty = req.param(1).and_then(|v| v.as_bool()).unwrap_or(false);
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let txs = read::list_transactions(&handle.dir)?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();
    let received = received_by_address(&txs, &st, minconf);
    let mut by_label = received_by_label(&received, &label_map);

    if include_empty {
        // Every known label, plus the default label "" if any wallet address is unlabelled.
        for label in label_map.values() {
            by_label.entry(label.clone()).or_insert((0, i64::MAX));
        }
        if read::all_addresses(handle.network, &handle.dir)
            .iter()
            .any(|a| !label_map.contains_key(a))
        {
            by_label.entry(String::new()).or_insert((0, i64::MAX));
        }
    }

    let out: Vec<Value> = by_label
        .into_iter()
        .map(|(label, (amount, conf))| {
            json!({
                "amount": zats_to_value(amount),
                "confirmations": if conf == i64::MAX { 0 } else { conf },
                "label": label,
            })
        })
        .collect();
    Ok(Value::Array(out))
}

/// `listsinceblock [blockhash] [target_confirmations]` - the canonical restart-safe payment
/// poller: returns every wallet tx in blocks after `blockhash` (plus all unmined txs), and a
/// `lastblock` hash to feed back into the next call. Reorged-away transactions are rescanned
/// and re-reported by the sync engine rather than tracked separately, so `removed` is always
/// empty.
pub fn listsinceblock(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let st = handle.status();

    // Param 0: list activity *since* this block (exclusive). Omitted/empty means everything.
    let since_height = match req.param(0).and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        Some(hash) => Some(
            read::block_height_by_hash(&handle.dir, hash)?
                .ok_or_else(|| RpcError::invalid_address_or_key("Block not found"))?,
        ),
        None => None,
    };
    // Param 1: which depth's block hash to return as `lastblock` (>= 1, like Bitcoin Core).
    let target_conf = match req.param(1) {
        None | Some(Value::Null) => 1u32,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 1 => n as u32,
            _ => return Err(RpcError::invalid_parameter("Invalid target_confirmations")),
        },
    };

    let txs = read::list_transactions(&handle.dir)?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();
    let mut transactions: Vec<Value> = Vec::new();
    for tx in &txs {
        let include = match (tx.mined_height, since_height) {
            (Some(h), Some(since)) => h > since,
            // Unmined txs (and everything, when no reference block was given).
            _ => true,
        };
        if !include {
            continue;
        }
        let confirmations = tx_confirmations(&st, tx);
        transactions.extend(tx_entries(tx, &label_map, confirmations, None));
    }

    // `lastblock` is the hash of the block that currently has `target_confirmations`
    // confirmations: pass it back as the next call's blockhash and any tx with fewer
    // confirmations at this point is reported again rather than missed.
    let lastblock = st
        .fully_scanned
        .and_then(|scanned| scanned.checked_sub(target_conf - 1))
        .and_then(|h| read::block_info_at(&handle.dir, h).ok().flatten())
        .map(|(hash, _)| hash)
        .unwrap_or_default();

    Ok(json!({
        "transactions": transactions,
        "removed": [],
        "lastblock": lastblock,
    }))
}

pub async fn gettransaction(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let txid = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("gettransaction requires a txid"))?;
    let handle = state.registry.get(wallet)?.clone();
    let st = handle.status();
    let rec = read::get_transaction(&handle.dir, txid)?
        .ok_or_else(|| RpcError::invalid_address_or_key("Invalid or non-wallet transaction id"))?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();

    let mut details = Vec::new();
    for out in &rec.outputs {
        if out.is_change {
            continue;
        }
        let Some(category) =
            output_category(out.from_account.is_some(), out.to_account.is_some())
        else {
            continue;
        };
        let amount = if category == "send" { -out.value } else { out.value };
        let mut d = json!({
            "address": out.to_address.clone().unwrap_or_default(),
            "category": category,
            "amount": signed_zats_to_value(amount),
            "vout": out.output_index,
            "label": out.to_address.as_ref().and_then(|a| label_map.get(a).cloned()).unwrap_or_default(),
        });
        if category == "send" {
            d["abandoned"] = json!(rec.expired_unmined);
            if let Some(fee) = rec.fee_paid {
                d["fee"] = signed_zats_to_value(-(fee as i64));
            }
        }
        details.push(d);
    }

    // `hex`: stored raw for txs we created; otherwise fetch the full tx on demand (received
    // txs are only seen as compact blocks until enhanced).
    let hex_str = match &rec.raw {
        Some(raw) => hex::encode(raw),
        None => match parse_txid(&rec.txid_hex) {
            Some(txid) => handle
                .get_raw_tx(txid)
                .await
                .ok()
                .flatten()
                .map(|raw| hex::encode(raw.data))
                .unwrap_or_default(),
            None => String::new(),
        },
    };

    let amount = gettransaction_amount(rec.account_balance_delta, rec.fee_paid);
    let confirmations = tx_confirmations(&st, &rec);
    let mut obj = json!({
        "amount": signed_zats_to_value(amount),
        "confirmations": confirmations,
        "txid": rec.txid_hex,
        "time": rec.block_time.unwrap_or(0),
        "timereceived": rec.block_time.unwrap_or(0),
        "bip125-replaceable": "no",
        "details": details,
        "hex": hex_str,
    });
    if let Some(fee) = rec.fee_paid {
        obj["fee"] = signed_zats_to_value(-(fee as i64));
    }
    if let Some(h) = rec.mined_height {
        obj["blockheight"] = json!(h);
    }
    Ok(obj)
}

pub fn listunspent(state: &AppState, wallet: Option<&str>, req: &RpcRequest) -> Result<Value, RpcError> {
    let minconf = req.param(0).and_then(|v| v.as_i64()).unwrap_or(1);
    let maxconf = req.param(1).and_then(|v| v.as_i64()).unwrap_or(9_999_999);
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    // Each unspent Orchard note is reported as one entry. The (txid, vout) refers to the
    // shielded action that created the note; there is no transparent scriptPubKey.
    let notes = read::list_unspent(handle.network, &handle.dir)?;
    let arr: Vec<Value> = notes
        .iter()
        .map(|n| {
            let conf = st.confirmations(n.mined_height);
            (conf, n)
        })
        .filter(|(conf, _)| *conf >= minconf && *conf <= maxconf)
        .map(|(conf, n)| {
            json!({
                "txid": n.txid,
                "vout": n.vout,
                "address": "",
                "amount": zats_to_value(n.value),
                "confirmations": conf,
                "spendable": true,
                "solvable": true,
                // Bitcoin Core: confirmed notes and the wallet's *own* unconfirmed change
                // are safe to spend; a foreign note surfaced at 0-conf (minconf=0, fed by
                // the mempool stream) is not.
                "safe": conf > 0 || n.trusted,
            })
        })
        .collect();
    Ok(Value::Array(arr))
}

/// Whether a positional param was supplied with a value that "turns it on" (anything but
/// null/false/empty array). Used to reject unsupported options that would change money
/// semantics if silently ignored.
fn param_engaged(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Array(a) => !a.is_empty(),
        _ => true,
    }
}

fn build_payment(network: &crate::network::ZNetwork, addr: &str, amount: &Value) -> Result<Payment, RpcError> {
    let zaddr = crate::address::parse_recipient_on_network(network, addr)?;
    let zats = value_to_zats(amount)?;
    Ok(Payment::without_memo(zaddr, zats))
}

pub async fn sendtoaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("sendtoaddress requires an address"))?;
    let amount = req
        .param(1)
        .ok_or_else(|| RpcError::invalid_params("sendtoaddress requires an amount"))?;
    // Params 2/3 (comment, comment_to) are metadata and safe to ignore, but
    // subtractfeefromamount changes who pays the fee: silently ignoring it would debit the
    // sender more than the caller intended. Reject it until it is implemented.
    if req.param(4).is_some_and(param_engaged) {
        return Err(RpcError::invalid_parameter(
            "subtractfeefromamount is not supported (fees are ZIP-317, paid by the sender)",
        ));
    }
    // Param 9 (fee_rate) is an explicit fee instruction. Fees are ZIP-317 - computed by the
    // wallet, never settable - so reject it rather than silently charging a different fee
    // than the caller specified. (conf_target/estimate_mode are estimation *hints* and safe
    // to ignore: the conventional fee already buys next-block inclusion.)
    if req.param(9).is_some_and(param_engaged) {
        return Err(RpcError::invalid_parameter(
            "fee_rate is not supported (fees are ZIP-317, computed by the wallet)",
        ));
    }
    let handle = state.registry.get(wallet)?.clone();
    let payment = build_payment(&handle.network, addr, amount)?;
    let request = TransactionRequest::new(vec![payment])
        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e:?}")))?;
    let txid = handle.send(request).await?;
    Ok(Value::String(txid.to_string()))
}

pub async fn sendmany(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // params: [dummy, { "addr": amount, ... }, minconf, comment, subtractfeefrom, ...].
    // The dummy is ignored (legacy) and minconf is an "ignored dummy value" in Bitcoin Core
    // too, but subtractfeefrom changes who pays the fee - reject it rather than silently
    // sending different amounts than the caller intended.
    let recipients = req
        .param(1)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("sendmany requires an address->amount object"))?;
    if req.param(4).is_some_and(param_engaged) {
        return Err(RpcError::invalid_parameter(
            "subtractfeefrom is not supported (fees are ZIP-317, paid by the sender)",
        ));
    }
    // Param 8 (fee_rate): an explicit fee instruction - rejected for the same reason as
    // sendtoaddress's (the wallet computes the ZIP-317 fee; it is never settable).
    if req.param(8).is_some_and(param_engaged) {
        return Err(RpcError::invalid_parameter(
            "fee_rate is not supported (fees are ZIP-317, computed by the wallet)",
        ));
    }
    let handle = state.registry.get(wallet)?.clone();
    let mut payments = Vec::new();
    for (addr, amount) in recipients {
        payments.push(build_payment(&handle.network, addr, amount)?);
    }
    if payments.is_empty() {
        return Err(RpcError::invalid_params("sendmany requires at least one recipient"));
    }
    let request = TransactionRequest::new(payments)
        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e:?}")))?;
    let txid = handle.send(request).await?;
    Ok(Value::String(txid.to_string()))
}

/// Bitcoin Core clamps the unlock timeout to this many seconds (~3.17 years); larger values
/// are silently reduced rather than rejected.
const MAX_UNLOCK_TIMEOUT_SECS: i64 = 100_000_000;

pub async fn walletpassphrase(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let passphrase = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("walletpassphrase requires a passphrase"))?;
    // Timeout (seconds) is required and must be a non-negative integer; huge values are clamped.
    let timeout = req
        .param(1)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| RpcError::invalid_parameter("walletpassphrase requires an integer timeout (seconds)"))?;
    if timeout < 0 {
        return Err(RpcError::invalid_parameter("Timeout cannot be negative."));
    }
    if passphrase.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    let timeout = timeout.min(MAX_UNLOCK_TIMEOUT_SECS);
    let handle = state.registry.get(wallet)?.clone();
    handle.unlock(Passphrase::from(passphrase.to_owned()), timeout).await?;
    Ok(Value::Null)
}

pub async fn walletlock(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?.clone();
    handle.lock().await?;
    Ok(Value::Null)
}

pub async fn encryptwallet(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let passphrase = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("encryptwallet requires a passphrase"))?;
    if passphrase.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    let handle = state.registry.get(wallet)?.clone();
    handle.encrypt_wallet(Passphrase::from(passphrase.to_owned())).await?;
    // Unlike Bitcoin Core, the mnemonic/seed is unchanged (no new backup needed) - only the
    // at-rest wrapping changed, so the wallet is now locked and needs walletpassphrase.
    Ok(Value::String(
        "wallet encrypted; the mnemonic is now passphrase-protected. \
         Call walletpassphrase to unlock before sending."
            .to_string(),
    ))
}

pub async fn walletpassphrasechange(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let old = req
        .param(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("walletpassphrasechange requires the old passphrase"))?;
    let new = req
        .param(1)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("walletpassphrasechange requires the new passphrase"))?;
    if new.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    let handle = state.registry.get(wallet)?.clone();
    handle
        .change_passphrase(Passphrase::from(old.to_owned()), Passphrase::from(new.to_owned()))
        .await?;
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::read::{TxOutputRecord, TxRecord};

    fn status(fully_scanned: u32) -> SyncStatus {
        SyncStatus {
            fully_scanned: Some(fully_scanned),
            chain_tip: Some(fully_scanned + 5),
            ..Default::default()
        }
    }

    fn out(
        from: bool,
        to: bool,
        value: i64,
        addr: Option<&str>,
        is_change: bool,
    ) -> TxOutputRecord {
        TxOutputRecord {
            pool: 3,
            output_index: 0,
            from_account: from.then(uuid::Uuid::new_v4),
            to_account: to.then(uuid::Uuid::new_v4),
            to_address: addr.map(str::to_string),
            value,
            is_change,
        }
    }

    fn tx(
        mined: Option<u32>,
        expired: bool,
        fee: Option<u64>,
        outputs: Vec<TxOutputRecord>,
    ) -> TxRecord {
        TxRecord {
            mined_height: mined,
            txid_hex: "ab".repeat(32),
            expiry_height: None,
            account_balance_delta: 0,
            fee_paid: fee,
            sent_note_count: 0,
            received_note_count: 0,
            block_time: Some(1_700_000_000),
            expired_unmined: expired,
            outputs,
            raw: None,
        }
    }

    #[test]
    fn receive_entry_shape() {
        let t = tx(Some(100), false, None, vec![out(false, true, 150_000_000, Some("ua"), false)]);
        let st = status(102);
        let e = tx_entries(&t, &HashMap::new(), tx_confirmations(&st, &t), None);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0]["category"], "receive");
        assert_eq!(e[0]["amount"].to_string(), "1.50000000");
        assert_eq!(e[0]["confirmations"], json!(3));
        assert_eq!(e[0]["blockheight"], json!(100));
        assert_eq!(e[0]["trusted"], json!(true));
        // `abandoned`/`fee` ride on send entries only.
        assert!(e[0].get("abandoned").is_none());
        assert!(e[0].get("fee").is_none());
    }

    #[test]
    fn send_entry_is_negative_with_fee() {
        let t = tx(
            Some(50),
            false,
            Some(10_000),
            vec![out(true, false, 150_000_000, Some("dest"), false)],
        );
        let e = tx_entries(&t, &HashMap::new(), 1, None);
        assert_eq!(e[0]["category"], "send");
        assert_eq!(e[0]["amount"].to_string(), "-1.50000000");
        assert_eq!(e[0]["fee"].to_string(), "-0.00010000");
        assert_eq!(e[0]["abandoned"], json!(false));
    }

    #[test]
    fn change_and_internal_outputs_are_skipped() {
        let t = tx(
            Some(50),
            false,
            None,
            vec![
                out(true, true, 1, Some("self"), true),  // change
                out(true, true, 2, Some("self"), false), // internal transfer
            ],
        );
        assert!(tx_entries(&t, &HashMap::new(), 1, None).is_empty());
    }

    #[test]
    fn expired_tx_is_conflicted_and_abandoned() {
        let t = tx(None, true, Some(10_000), vec![out(true, false, 5, Some("dest"), false)]);
        let st = status(100);
        let conf = tx_confirmations(&st, &t);
        assert_eq!(conf, -1);
        let e = tx_entries(&t, &HashMap::new(), conf, None);
        assert_eq!(e[0]["confirmations"], json!(-1));
        assert_eq!(e[0]["abandoned"], json!(true));
        assert_eq!(e[0]["trusted"], json!(false));
    }

    #[test]
    fn label_filter_keeps_only_matches() {
        let mut labels = HashMap::new();
        labels.insert("dest".to_string(), "alice".to_string());
        let t = tx(Some(50), false, None, vec![out(false, true, 5, Some("dest"), false)]);
        assert_eq!(tx_entries(&t, &labels, 1, Some("alice")).len(), 1);
        assert!(tx_entries(&t, &labels, 1, Some("bob")).is_empty());
        assert_eq!(tx_entries(&t, &labels, 1, None).len(), 1);
    }

    #[test]
    fn received_by_address_groups_and_respects_minconf() {
        let st = status(100);
        let txs = vec![
            tx(Some(100), false, None, vec![out(false, true, 100, Some("a"), false)]), // 1 conf
            tx(Some(91), false, None, vec![out(false, true, 50, Some("a"), false)]),   // 10 conf
            tx(None, false, None, vec![out(false, true, 7, Some("a"), false)]),        // 0 conf
            tx(None, true, None, vec![out(false, true, 9, Some("a"), false)]),         // expired: -1 conf
            tx(Some(100), false, None, vec![out(true, true, 11, Some("a"), true)]),    // change: skipped
        ];
        let m = received_by_address(&txs, &st, 1);
        let (amt, conf, txids) = m.get("a").cloned().unwrap();
        assert_eq!(amt, 150);
        assert_eq!(conf, 1); // confirmations of the most recent counted tx
        assert_eq!(txids.len(), 2);
        // minconf 0 picks up the unmined receive but still never the expired/change outputs.
        assert_eq!(received_by_address(&txs, &st, 0).get("a").unwrap().0, 157);
    }

    #[test]
    fn received_by_label_groups_and_defaults_to_empty_label() {
        let st = status(100);
        let txs = vec![
            tx(Some(91), false, None, vec![out(false, true, 100, Some("a1"), false)]),
            tx(Some(95), false, None, vec![out(false, true, 50, Some("a2"), false)]),
            tx(Some(100), false, None, vec![out(false, true, 7, Some("b"), false)]),
        ];
        let mut labels = HashMap::new();
        labels.insert("a1".to_string(), "alice".to_string());
        labels.insert("a2".to_string(), "alice".to_string());
        // "b" is unlabelled -> default label "".
        let received = received_by_address(&txs, &st, 1);
        let by_label = received_by_label(&received, &labels);
        // Amounts sum per label; confirmations are the minimum across the label's addresses.
        assert_eq!(by_label.get("alice"), Some(&(150, 6)));
        assert_eq!(by_label.get(""), Some(&(7, 1)));
    }

    #[test]
    fn gettransaction_amount_adds_fee_back() {
        // Wallet-funded: delta = -(payment + fee); `amount` must be -payment.
        assert_eq!(gettransaction_amount(-150_010_000, Some(10_000)), -150_000_000);
        // Pure receive: no fee known, delta already the received value.
        assert_eq!(gettransaction_amount(250_000_000, None), 250_000_000);
        // Self-transfer: delta is just -fee; nets to 0.
        assert_eq!(gettransaction_amount(-10_000, Some(10_000)), 0);
    }

    #[test]
    fn confirmations_anchor_to_fully_scanned() {
        let st = status(100); // fully_scanned 100, chain_tip 105
        assert_eq!(st.confirmations(Some(100)), 1);
        assert_eq!(st.confirmations(Some(98)), 3);
        // Mined above the fully-scanned height (scanned-ahead range): not yet counted,
        // matching what getblockcount-based client math would compute.
        assert_eq!(st.confirmations(Some(101)), 0);
        assert_eq!(st.confirmations(None), 0);
    }
}
