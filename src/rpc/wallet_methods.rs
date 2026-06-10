//! Wallet RPCs mapped onto Orchard shielded operations.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};
use zcash_protocol::TxId;
use zip321::{Payment, TransactionRequest};

use crate::amount::{signed_zats_to_value, value_to_zats, zats_to_value};
use crate::error::RpcError;
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::{labels, read};

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
    Ok(json!({
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
    }))
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

pub fn listtransactions(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let count = req.param(1).and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let skip = req.param(2).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let txs = read::list_transactions(&handle.dir)?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();

    let mut entries: Vec<Value> = Vec::new();
    for tx in &txs {
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
            let mut entry = json!({
                "address": address,
                "category": category,
                "amount": signed_zats_to_value(amount),
                "label": label,
                "vout": out.output_index,
                "confirmations": st.confirmations(tx.mined_height),
                "txid": tx.txid_hex,
                "time": tx.block_time.unwrap_or(0),
                "timereceived": tx.block_time.unwrap_or(0),
                "bip125-replaceable": "no",
                "trusted": tx.mined_height.is_some(),
            });
            if category == "send" {
                if let Some(fee) = tx.fee_paid {
                    entry["fee"] = signed_zats_to_value(-(fee as i64));
                }
            }
            if let Some(h) = tx.mined_height {
                entry["blockheight"] = json!(h);
            }
            entries.push(entry);
        }
    }

    // `entries` is oldest-first; return the most recent `count` after skipping `skip`.
    let total = entries.len();
    let end = total.saturating_sub(skip);
    let start = end.saturating_sub(count);
    Ok(Value::Array(entries[start..end].to_vec()))
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
                .map(hex::encode)
                .unwrap_or_default(),
            None => String::new(),
        },
    };

    // Bitcoin Core's `amount` excludes the fee (reported separately in `fee`): for a
    // wallet-funded tx the balance delta is -(payments + fee), so add the fee back.
    // `fee_paid` is only known when the wallet funded the tx; for pure receives it is
    // None and the delta is already the received amount. A self-transfer nets to 0.
    let amount = rec.account_balance_delta + rec.fee_paid.unwrap_or(0) as i64;
    let mut obj = json!({
        "amount": signed_zats_to_value(amount),
        "confirmations": st.confirmations(rec.mined_height),
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
                "safe": true,
            })
        })
        .collect();
    Ok(Value::Array(arr))
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
    // params: [dummy, { "addr": amount, ... }, ...]; the first arg is ignored (legacy).
    let recipients = req
        .param(1)
        .and_then(|v| v.as_object())
        .ok_or_else(|| RpcError::invalid_params("sendmany requires an address->amount object"))?;
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

pub async fn walletpassphrase(
    state: &AppState,
    wallet: Option<&str>,
    _req: &RpcRequest,
) -> Result<Value, RpcError> {
    // Compat: unlock the seed from the configured age identity. The timeout argument is
    // accepted but not enforced in v1 (the seed remains until walletlock or shutdown).
    let handle = state.registry.get(wallet)?.clone();
    handle.unlock().await?;
    Ok(Value::Null)
}

pub async fn walletlock(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?.clone();
    handle.lock().await?;
    Ok(Value::Null)
}
