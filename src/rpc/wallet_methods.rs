//! Wallet RPCs mapped onto Orchard shielded operations.

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU32;

use serde_json::{json, Map, Value};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::TxId;
use zip321::{Payment, TransactionRequest};

use crate::amount::{signed_zats_to_value, value_to_zats, zats_to_value};
use crate::config::SendPrivacy;
use crate::error::RpcError;
use crate::operations::{AsyncOperation, ContextInfo, OperationId};
use crate::server::jsonrpc::RpcRequest;
use crate::state::AppState;
use crate::wallet::store::Passphrase;
use crate::wallet::{labels, read, SyncStatus};

pub(crate) fn opt_str(req: &RpcRequest, i: usize) -> Option<String> {
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

/// `listwallets` - the names of all loaded wallets (every `[wallets.<name>]` in the config).
pub(crate) fn listwallets(state: &AppState) -> Result<Value, RpcError> {
    Ok(json!(state.registry.names()))
}

/// `getnewaddress [label] [address_type]` - a fresh diversified unified address for the wallet's
/// account (new diversifier, not a new derivation path).
///
/// `address_type` doubles as a per-call receiver override (zallet's `receiver_types`, expressed as
/// a single string for Bitcoin-RPC conformance):
/// - empty / `"unified"` / `"default"` → the wallet's configured `default_receivers`,
/// - a single pool name (`"orchard"`, `"sapling"`),
/// - a comma-separated list (`"sapling,orchard"`).
///
/// Every requested receiver must be a pool enabled on the wallet, else `-8`.
pub(crate) async fn getnewaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = opt_str(req, 0).filter(|s| !s.is_empty());
    // Param 1 (address_type): parse the receiver-override *syntax* before resolving the wallet,
    // so an unknown type is a `-5` regardless of which wallet is targeted (and even when no
    // wallet exists). Enablement is wallet-specific and checked once the handle is in hand.
    let raw_type = opt_str(req, 1);
    let requested = parse_receiver_tokens(raw_type.as_deref())?;
    let handle = state.registry.get(wallet)?.clone();
    if let Some(set) = &requested {
        if !set.is_subset_of(&handle.enabled_pools) {
            return Err(RpcError::invalid_parameter(format!(
                "address type requests a receiver not enabled on this wallet; enabled pools: {}",
                handle.enabled_pools.display_names()
            )));
        }
    }
    let addr = handle.get_new_address(label, requested).await?;
    Ok(Value::String(addr))
}

/// Parse the `getnewaddress` `address_type` argument into an optional receiver set, validating
/// only its syntax (wallet-independent). Returns `Ok(None)` for the default (empty / `unified` /
/// `default`), `Ok(Some(set))` for an explicit single pool or comma-separated list, or a `-5` for
/// an unknown token. Whether the wallet actually enables those pools is checked by the caller.
fn parse_receiver_tokens(
    address_type: Option<&str>,
) -> Result<Option<crate::pools::PoolSet>, RpcError> {
    use crate::pools::{Pool, PoolSet};
    let Some(raw) = address_type.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if raw.eq_ignore_ascii_case("unified") || raw.eq_ignore_ascii_case("default") {
        return Ok(None);
    }
    let mut pools = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        let pool = Pool::from_config_str(token).map_err(|_| {
            RpcError::invalid_address_or_key(format!("Unknown address type '{token}'"))
        })?;
        pools.push(pool);
    }
    let set = PoolSet::new(pools)
        .map_err(|e| RpcError::invalid_address_or_key(format!("Invalid address type: {e}")))?;
    Ok(Some(set))
}

/// Map `getbalance`'s optional `minconf` argument onto a [`ConfirmationsPolicy`]. Omitted
/// (or null) keeps the wallet's configured policy (`[spend]`; ZIP-315 trusted-3/untrusted-10
/// by default) - so the no-argument balance always equals what a send can actually spend.
/// An explicit `minconf` overrides both bounds symmetrically (Bitcoin Core honors `minconf`
/// the same way). Shielded notes can never be spent at 0 confirmations, so `minconf` 0 is
/// served as 1, like Zallet's balance RPCs.
fn minconf_policy(
    v: Option<&Value>,
    default: ConfirmationsPolicy,
) -> Result<ConfirmationsPolicy, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(default),
        Some(v) => match v.as_i64() {
            // Bitcoin Core accepts any integer here; depths below 1 behave like its
            // default of 0, which for shielded notes means the 1-confirmation minimum.
            Some(n) => {
                let min = u32::try_from(n.max(1)).unwrap_or(u32::MAX);
                Ok(ConfirmationsPolicy::new_symmetrical(
                    NonZeroU32::new(min).expect("clamped to >= 1"),
                    // cfg(transparent-inputs) arg: an explicit minconf must not loosen
                    // transparent spends to 0-conf.
                    false,
                ))
            }
            None => Err(RpcError::type_error("minconf must be a number")),
        },
    }
}

/// Validate `getbalance`'s legacy first argument, which Bitcoin Core requires to be
/// excluded or `"*"` (anything else is `-32 RPC_METHOD_DEPRECATED`).
pub(crate) fn check_balance_dummy(v: Option<&Value>) -> Result<(), RpcError> {
    match v {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(s)) if s == "*" => Ok(()),
        Some(Value::String(_)) => Err(RpcError::new(
            crate::error::codes::RPC_METHOD_DEPRECATED,
            "dummy first argument must be excluded or set to \"*\".",
        )),
        Some(_) => Err(RpcError::type_error("dummy must be a string")),
    }
}

/// `getbalance ["*"] [minconf]` - the spendable balance under the wallet's confirmations
/// policy (or an explicit `minconf` override; see [`minconf_policy`]).
pub(crate) fn getbalance(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    check_balance_dummy(req.param(0))?;
    let handle = state.registry.get(wallet)?;
    let policy = minconf_policy(req.param(1), handle.confirmations)?;
    let info = read::balance(handle.network, &handle.dir, policy)?;
    Ok(zats_to_value(info.total_spendable))
}

/// `getunconfirmedbalance` - value received but not yet spendable under the wallet's
/// confirmations policy (incoming 0-conf payments surface here via the mempool stream).
pub(crate) fn getunconfirmedbalance(
    state: &AppState,
    wallet: Option<&str>,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir, handle.confirmations)?;
    Ok(zats_to_value(info.pending))
}

/// `getbalances` - the modern (Bitcoin Core 0.19+) balance triple. The legacy `watchonly`
/// object is always omitted: like Bitcoin Core's descriptor wallets, a zecd watch-only
/// (UFVK) wallet reports its funds under `mine` (the addresses are the wallet's own; only
/// signing is impossible).
pub(crate) fn getbalances(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir, handle.confirmations)?;
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

/// `getwalletinfo` - wallet metadata and balances; `scanning` reports sync progress and
/// `unlocked_until` appears only for passphrase-encrypted wallets, like Bitcoin Core.
pub(crate) fn getwalletinfo(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let info = read::balance(handle.network, &handle.dir, handle.confirmations)?;
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
        // False for a watch-only wallet (imported UFVK) - Bitcoin Core's signal for
        // "this wallet cannot sign" (`disable_private_keys` wallets report the same).
        "private_keys_enabled": !st.watch_only,
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

/// `getaddressinfo <address>` - ownership/validity details for an address; see
/// [`addressinfo_json`] for the response contract.
pub(crate) fn getaddressinfo(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "getaddressinfo requires an address")?;
    let handle = state.registry.get(wallet)?;
    let v = crate::address::validate(&handle.network, addr);
    let label = labels::get_label(&handle.dir, addr).ok().flatten();
    let ismine = v.is_valid && read::is_mine(handle.network, &handle.dir, addr);
    addressinfo_json(v, addr, ismine, label)
}

/// Build the `getaddressinfo` response. Bitcoin Core throws `-5 Invalid address` for an
/// undecodable address (`isvalid` belongs to `validateaddress`, not this method).
fn addressinfo_json(
    v: crate::address::Validation,
    addr: &str,
    ismine: bool,
    label: Option<String>,
) -> Result<Value, RpcError> {
    if !v.is_valid {
        return Err(RpcError::invalid_address_or_key("Invalid address"));
    }
    Ok(json!({
        "address": addr,
        // Real scriptPubKey for transparent addresses; shielded addresses have no script
        // form, so the field stays empty (same convention as validateaddress).
        "scriptPubKey": v.script_pub_key.unwrap_or_default(),
        "ismine": ismine,
        // Core: "If we know how to spend coins sent to this address, ignoring the possible
        // lack of private keys" - so a watch-only (UFVK) wallet's own addresses are solvable
        // too; the wallet-level signal is getwalletinfo.private_keys_enabled.
        "solvable": ismine,
        // "(DEPRECATED) Always false" in Bitcoin Core master: per-address watch-only died
        // with legacy wallets (descriptor wallets are watch-only per wallet, like zecd).
        "iswatchonly": false,
        "isscript": v.is_script,
        "iswitness": false,
        // Extension fields (a deliberate divergence from bitcoind): which pools this address can
        // receive into. Mirrors validateaddress - `isvalid_orchard` plus the full `receiver_types`
        // list (`transparent`/`sapling`/`orchard`), so a client sees what a `u1...` carries.
        "isvalid_orchard": v.is_orchard,
        "receiver_types": v.receiver_types,
        "labels": label.map(|l| vec![l]).unwrap_or_default(),
    }))
}

/// `setlabel <address> <label>` - label any valid address (foreign addresses too, as
/// Bitcoin Core's send-side address book allows). Labels live in the `labels.sqlite`
/// side-table, not the wallet DB.
pub(crate) fn setlabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "setlabel requires an address")?;
    let label = opt_str(req, 1).unwrap_or_default();
    let handle = state.registry.get(wallet)?;
    if !crate::address::validate(&handle.network, addr).is_valid {
        return Err(RpcError::invalid_address_or_key(format!(
            "Invalid Zcash address: {addr}"
        )));
    }
    labels::set_label(&handle.dir, addr, &label).map_err(RpcError::database_internal)?;
    Ok(Value::Null)
}

/// `getaddressesbylabel <label>` - every address carrying `label`, each with its `purpose`
/// (`receive` for the wallet's own addresses, `send` for labelled foreign ones).
pub(crate) fn getaddressesbylabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = req.require_str(0, "getaddressesbylabel requires a label")?;
    let handle = state.registry.get(wallet)?;
    let addrs =
        labels::addresses_for_label(&handle.dir, label).map_err(RpcError::database_internal)?;
    if addrs.is_empty() {
        // Bitcoin Core: -11 RPC_WALLET_INVALID_LABEL_NAME for a label with no addresses.
        return Err(RpcError::new(
            crate::error::codes::RPC_WALLET_INVALID_LABEL_NAME,
            format!("No addresses with label {label}"),
        ));
    }
    let mut map = Map::new();
    for a in addrs {
        // setlabel accepts foreign addresses too (Bitcoin Core's send-side address book);
        // those carry purpose "send", the wallet's own addresses "receive".
        let purpose = if read::is_mine(handle.network, &handle.dir, &a) {
            "receive"
        } else {
            "send"
        };
        map.insert(a, json!({ "purpose": purpose }));
    }
    Ok(Value::Object(map))
}

/// `listlabels` - the sorted, de-duplicated set of labels in use.
pub(crate) fn listlabels(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let all = labels::all(&handle.dir).unwrap_or_default();
    let set: BTreeSet<String> = all.into_values().collect();
    Ok(json!(set.into_iter().collect::<Vec<_>>()))
}

/// The per-output categories. A normal receive or send is one entry; a self-transfer (paid
/// from the account back to one of its own addresses) is Bitcoin Core's send + receive
/// pair, so consolidations and own-address test payments show up in history. Change stays
/// skipped (callers filter it before asking).
fn output_categories(from_account: bool, to_account: bool) -> &'static [&'static str] {
    match (from_account, to_account) {
        (false, true) => &["receive"],
        (true, false) => &["send"],
        (true, true) => &["send", "receive"],
        (false, false) => &[],
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

/// The `time`/`timereceived` of a wallet transaction: the block time once mined, else when
/// the wallet first saw it (recorded by the mempool stream) or created it (librustzcash's
/// `created` column, set for wallet-authored sends). Bitcoin Core's `GetTxTime` /
/// `nTimeReceived` analog.
fn tx_time(tx: &read::TxRecord, first_seen: Option<i64>) -> i64 {
    tx.block_time
        .or(first_seen)
        .or(tx.created_time)
        .unwrap_or(0)
}

/// Append Bitcoin Core's `WalletTxToJSON` block/time fields, shared by `listtransactions`
/// entries, `listsinceblock`, and `gettransaction`:
/// - mined txs carry `blockhash`/`blockheight`/`blockindex`/`blocktime` (hash/index omitted
///   in the rare case the wallet hasn't scanned the block);
/// - unmined txs carry `trusted` instead, like Bitcoin Core: trusted iff the wallet authored
///   the tx (it spends our notes) and it can still be mined;
/// - `walletconflicts` is always present (zecd tracks no conflict set, so it is empty);
/// - `time`/`timereceived` from [`tx_time`].
fn push_wallet_tx_fields(entry: &mut Value, tx: &read::TxRecord, time: i64) {
    let obj = entry.as_object_mut().expect("entry is a JSON object");
    if let Some(h) = tx.mined_height {
        if let Some(hash) = &tx.block_hash {
            obj.insert("blockhash".into(), json!(hash));
        }
        obj.insert("blockheight".into(), json!(h));
        if let Some(i) = tx.tx_index {
            obj.insert("blockindex".into(), json!(i));
        }
        if let Some(t) = tx.block_time {
            obj.insert("blocktime".into(), json!(t));
        }
    } else {
        obj.insert(
            "trusted".into(),
            json!(!tx.expired_unmined && tx.account_balance_delta < 0),
        );
    }
    obj.insert("walletconflicts".into(), json!([]));
    obj.insert("time".into(), json!(time));
    obj.insert("timereceived".into(), json!(time));
}

/// Append an output's shielded memo as extension fields beyond Bitcoin Core's set, using
/// zcashd's `z_viewtransaction` names: `memo` is the raw ZIP-302 bytes in hex, `memoStr`
/// the decoded text for text memos. Empty/absent memos add nothing.
fn push_memo_fields(entry: &mut Value, memo: Option<&[u8]>) {
    let Some(bytes) = memo else { return };
    let Some(parsed) = MemoBytes::from_bytes(bytes)
        .ok()
        .and_then(|mb| Memo::try_from(&mb).ok())
    else {
        return;
    };
    if matches!(parsed, Memo::Empty) {
        return;
    }
    let obj = entry.as_object_mut().expect("entry is a JSON object");
    obj.insert("memo".into(), json!(hex::encode(bytes)));
    if let Memo::Text(text) = &parsed {
        obj.insert("memoStr".into(), json!(&**text));
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
    time: i64,
    label_filter: Option<&str>,
) -> Vec<Value> {
    let mut entries = Vec::new();
    for out in &tx.outputs {
        if out.is_change {
            continue;
        }
        let categories = output_categories(out.from_account.is_some(), out.to_account.is_some());
        let address = out.to_address.clone().unwrap_or_default();
        let label = out
            .to_address
            .as_ref()
            .and_then(|a| label_map.get(a).cloned())
            .unwrap_or_default();
        if label_filter.is_some_and(|f| f != label) {
            continue;
        }
        for category in categories {
            let amount = if *category == "send" {
                -out.value
            } else {
                out.value
            };
            let mut entry = json!({
                "address": address,
                "category": category,
                "amount": signed_zats_to_value(amount),
                "label": label,
                "vout": out.output_index,
                "confirmations": confirmations,
                "txid": tx.txid_hex,
                "bip125-replaceable": "no",
            });
            if *category == "send" {
                // Bitcoin Core carries `abandoned` on send entries only.
                entry["abandoned"] = json!(tx.expired_unmined);
                if let Some(fee) = tx.fee_paid {
                    entry["fee"] = signed_zats_to_value(-(fee as i64));
                }
            }
            push_memo_fields(&mut entry, out.memo.as_deref());
            push_wallet_tx_fields(&mut entry, tx, time);
            entries.push(entry);
        }
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

/// The most recent `count` history entries after skipping `from`, in oldest-to-newest order,
/// shared by `listtransactions` and `z_listtransactions`. Rather than expanding the whole
/// wallet then slicing the tail, fetch transactions newest-first in growing pages and expand
/// only as many as the window needs (zcashd's "iterate backwards until `count + from` items"
/// done in SQL).
///
/// `expand` maps one transaction to its entries in natural (within-tx) order; each tx's
/// entries are pushed reversed so that, after a final reverse of the accumulated
/// newest-first list, the original within-tx order is restored - matching the build-all-then-
/// slice output exactly.
fn paginate_history(
    wallet_dir: &std::path::Path,
    from: usize,
    count: usize,
    expand: impl Fn(&read::TxRecord) -> Vec<Value>,
) -> Result<Vec<Value>, RpcError> {
    let want = from.saturating_add(count);
    // Grow the transaction page until the window is covered or the wallet is exhausted. Once a
    // page returns fewer txs than requested there are no more, so the doubling is bounded by
    // the wallet size. We over-fetch transactions (not entries): a tx may expand to several
    // entries, so a page of N txs yields >= N entries - enough once N txs cover the window.
    let mut limit: u32 = (want.max(1)).min(u32::MAX as usize) as u32;
    loop {
        let query = read::TxQuery {
            start_height: None,
            end_height: None,
            offset: 0,
            limit: Some(limit),
            newest_first: true,
        };
        let txs = read::query_transactions(wallet_dir, &query)?;
        let full_page = txs.len() as u32 >= limit;
        let entries = window_history_from_txs(&txs, from, count, &expand);
        // The window is fully covered when either we produced exactly the requested count, or
        // there are no more transactions to fetch (a non-full page is the whole tail).
        if entries.len() >= count || !full_page {
            return Ok(entries);
        }
        // More transactions may exist and the window isn't covered yet; double the page,
        // saturating at u32::MAX (the next pass then sees a non-full page and returns).
        match limit.checked_mul(2) {
            Some(next) => limit = next,
            None => {
                if limit == u32::MAX {
                    return Ok(entries);
                }
                limit = u32::MAX;
            }
        }
    }
}

/// The pure windowing core of [`paginate_history`]: given transactions in newest-first order
/// (a superset of the window suffices), expand each - pushing its entries reversed - to build
/// the newest-first entry list, then take the `[from, from+count)` slice and reverse it back
/// to oldest-first. Equivalent to the old "expand all oldest-first, then return the
/// `count`-long tail after skipping `from`", but without materializing the whole history.
fn window_history_from_txs(
    newest_first_txs: &[read::TxRecord],
    from: usize,
    count: usize,
    expand: impl Fn(&read::TxRecord) -> Vec<Value>,
) -> Vec<Value> {
    let want = from.saturating_add(count);
    let mut entries: Vec<Value> = Vec::new();
    for tx in newest_first_txs {
        let mut tx_entries = expand(tx);
        tx_entries.reverse();
        entries.extend(tx_entries);
        // Short-circuit once enough newest-first entries to satisfy the window are in hand.
        if entries.len() >= want {
            break;
        }
    }
    let start = from.min(entries.len());
    let end = want.min(entries.len());
    let mut window = entries[start..end].to_vec();
    window.reverse();
    window
}

/// Parse `listtransactions`/`z_listtransactions`'s `count` and `from` positional args with
/// Bitcoin Core's strictness: a negative value is `-8`, a non-integer is `-3`.
fn count_from_params(
    req: &RpcRequest,
    count_i: usize,
    from_i: usize,
) -> Result<(usize, usize), RpcError> {
    let count = match req.param(count_i).filter(|v| !v.is_null()) {
        None => 10,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => n as usize,
            Some(_) => return Err(RpcError::invalid_parameter("Negative count")),
            None => return Err(RpcError::type_error("count must be a number")),
        },
    };
    let from = match req.param(from_i).filter(|v| !v.is_null()) {
        None => 0,
        Some(v) => match v.as_i64() {
            Some(n) if n >= 0 => n as usize,
            Some(_) => return Err(RpcError::invalid_parameter("Negative from")),
            None => return Err(RpcError::type_error("from must be a number")),
        },
    };
    Ok((count, from))
}

/// `listtransactions [label] [count] [from]` - the most recent wallet history entries, one
/// per non-change output (see [`tx_entries`] for the entry shape and sign conventions).
pub(crate) fn listtransactions(
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
    let (count, skip) = count_from_params(req, 1, 2)?;
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let label_map = labels::all(&handle.dir).unwrap_or_default();
    let first_seen = labels::first_seen_all(&handle.dir).unwrap_or_default();

    let entries = paginate_history(&handle.dir, skip, count, |tx| {
        let confirmations = tx_confirmations(&st, tx);
        let time = tx_time(tx, first_seen.get(&tx.txid_hex).copied());
        tx_entries(tx, &label_map, confirmations, time, label_filter.as_deref())
    })?;
    Ok(Value::Array(entries))
}

/// The shielded value pool name for a `v_tx_outputs.output_pool` code (zcashd's `pool`
/// field): 0 = transparent, 2 = Sapling, 3 = Orchard.
fn pool_name(pool: i64) -> &'static str {
    match pool {
        0 => "transparent",
        2 => "sapling",
        3 => "orchard",
        _ => "unknown",
    }
}

/// zcashd's per-transaction `status` (`WalletTxToJSON`): "mined" once it has a block, else
/// "expired" for an expired-unmined tx, else "waiting". We do not surface "expiringsoon" - it
/// needs the expiry-vs-tip window, which the wallet view does not cheaply expose here.
fn z_tx_status(tx: &read::TxRecord) -> &'static str {
    if tx.mined_height.is_some() {
        "mined"
    } else if tx.expired_unmined {
        "expired"
    } else {
        "waiting"
    }
}

/// Build the `z_listtransactions` entries for one transaction: one object per non-change
/// output, in zcashd's vocabulary (`pool`/`outindex`/`amountZat`/`outgoing`/`status`, plus
/// `memo`/`memoStr`). Self-transfers pair send+receive like `listtransactions`. Each entry
/// repeats the tx-level fields, as zcashd's flattened history does.
fn z_tx_entries(tx: &read::TxRecord, confirmations: i64, time: i64) -> Vec<Value> {
    let status = z_tx_status(tx);
    let mut entries = Vec::new();
    for out in &tx.outputs {
        if out.is_change {
            continue;
        }
        let categories = output_categories(out.from_account.is_some(), out.to_account.is_some());
        for category in categories {
            let send = *category == "send";
            let amount = if send { -out.value } else { out.value };
            let mut entry = json!({
                "txid": tx.txid_hex,
                "status": status,
                "confirmations": confirmations,
                "time": time,
                "walletconflicts": [],
                "pool": pool_name(out.pool),
                "category": category,
                "amount": signed_zats_to_value(amount),
                "amountZat": amount,
                "address": out.to_address.clone().unwrap_or_default(),
                "outindex": out.output_index,
                // Change is filtered above, but the key is always present (zcashd's
                // `walletInternal`); `outgoing` is true on the send side of a pairing.
                "change": false,
                "outgoing": send,
            });
            let obj = entry.as_object_mut().expect("entry is a JSON object");
            if let Some(h) = tx.mined_height {
                if let Some(hash) = &tx.block_hash {
                    obj.insert("blockhash".into(), json!(hash));
                }
                obj.insert("blockheight".into(), json!(h));
                if let Some(i) = tx.tx_index {
                    obj.insert("blockindex".into(), json!(i));
                }
                if let Some(t) = tx.block_time {
                    obj.insert("blocktime".into(), json!(t));
                }
            }
            // A non-zero expiry height (0 means "never expires").
            if let Some(e) = tx.expiry_height.filter(|e| *e != 0) {
                obj.insert("expiryheight".into(), json!(e));
            }
            if send {
                if let Some(fee) = tx.fee_paid {
                    obj.insert("fee".into(), signed_zats_to_value(-(fee as i64)));
                    obj.insert("feeZat".into(), json!(-(fee as i64)));
                }
            }
            push_memo_fields(&mut entry, out.memo.as_deref());
            entries.push(entry);
        }
    }
    entries
}

/// `z_listtransactions [count=10] [from=0] [includeWatchonly=false]` - a zecd extension (no
/// such method exists in zcashd) listing per-output history in zcashd's `z_*` vocabulary:
/// `pool`/`category`/`amount`/`amountZat`/`address`/`outindex`/`outgoing`/`status`, plus
/// `memo`/`memoStr` for shielded outputs and `fee`/`feeZat` on sends. Pagination is identical
/// to `listtransactions` (newest-first cursor, oldest-first output). `includeWatchonly` is
/// accepted and ignored (no watch-only support); there is no account filter.
pub(crate) fn z_listtransactions(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    // Positional args: count, from, includeWatchonly. count/from use zcashd's strictness
    // (negative -> -8, wrong type -> -3).
    let (count, from) = count_from_params(req, 0, 1)?;
    // includeWatchonly: accepted (bool or omitted) and ignored.
    match req.param(2) {
        None | Some(Value::Null) | Some(Value::Bool(_)) => {}
        Some(_) => return Err(RpcError::type_error("includeWatchonly must be a boolean")),
    }
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let first_seen = labels::first_seen_all(&handle.dir).unwrap_or_default();

    let entries = paginate_history(&handle.dir, from, count, |tx| {
        let confirmations = tx_confirmations(&st, tx);
        let time = tx_time(tx, first_seen.get(&tx.txid_hex).copied());
        z_tx_entries(tx, confirmations, time)
    })?;
    Ok(Value::Array(entries))
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
            let Some(addr) = &out.to_address else {
                continue;
            };
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
pub(crate) fn getreceivedbyaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "getreceivedbyaddress requires an address")?;
    let minconf = depth_param(req.param(1), "minconf", 1)?;
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
    // Push the single-address filter into SQL (sublinear) rather than scanning the whole
    // history; the aggregation then sees only this address's outputs.
    let txs = read::received_tx_records(&handle.dir, Some(addr))?;
    let total = received_by_address(&txs, &st, minconf)
        .remove(addr)
        .map(|(amt, _, _)| amt)
        .unwrap_or(0);
    Ok(zats_to_value(total))
}

/// `listreceivedbyaddress [minconf] [include_empty] [include_watchonly] [address_filter]` -
/// per-address received totals with the txids that paid them. There is no watch-only
/// support, so `include_watchonly` is accepted and ignored.
pub(crate) fn listreceivedbyaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let minconf = depth_param(req.param(0), "minconf", 1)?;
    let include_empty = req.param(1).and_then(|v| v.as_bool()).unwrap_or(false);
    let address_filter = req.param(3).and_then(|v| v.as_str()).map(str::to_string);
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let txs = read::received_tx_records(&handle.dir, None)?;
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
pub(crate) fn getreceivedbylabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let label = req.require_str(0, "getreceivedbylabel requires a label")?;
    let minconf = depth_param(req.param(1), "minconf", 1)?;
    let handle = state.registry.get(wallet)?;
    let addrs =
        labels::addresses_for_label(&handle.dir, label).map_err(RpcError::database_internal)?;
    if addrs.is_empty() {
        return Err(RpcError::wallet("Label not found in wallet"));
    }
    let st = handle.status();
    let txs = read::received_tx_records(&handle.dir, None)?;
    let received = received_by_address(&txs, &st, minconf);
    let total: u64 = addrs
        .iter()
        .filter_map(|a| received.get(a).map(|(amt, _, _)| *amt))
        .sum();
    Ok(zats_to_value(total))
}

/// `listreceivedbylabel [minconf] [include_empty] [include_watchonly]` - `listreceivedbyaddress`
/// aggregated per label. `include_watchonly` is accepted and ignored (no watch-only support).
pub(crate) fn listreceivedbylabel(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let minconf = depth_param(req.param(0), "minconf", 1)?;
    let include_empty = req.param(1).and_then(|v| v.as_bool()).unwrap_or(false);
    let handle = state.registry.get(wallet)?;
    let st = handle.status();
    let txs = read::received_tx_records(&handle.dir, None)?;
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
pub(crate) fn listsinceblock(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let st = handle.status();

    // Param 0: list activity *since* this block (exclusive). Omitted/empty means everything.
    let since_height = match req
        .param(0)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
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
            Some(n) if (1..=i64::from(u32::MAX)).contains(&n) => n as u32,
            _ => return Err(RpcError::invalid_parameter("Invalid target_confirmations")),
        },
    };

    // Push the since-height filter into SQL: `start_height = since + 1` keeps mined txs above
    // the reference block, and an open `end_height` admits all unmined txs (matching the prior
    // Rust predicate `h > since || mined_height IS NULL`). No reference block means everything.
    let query = read::TxQuery {
        start_height: since_height.map(|h| h.saturating_add(1)),
        end_height: None,
        offset: 0,
        limit: None,
        newest_first: false,
    };
    let txs = read::query_transactions(&handle.dir, &query)?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();
    let first_seen = labels::first_seen_all(&handle.dir).unwrap_or_default();
    let mut transactions: Vec<Value> = Vec::new();
    for tx in &txs {
        let confirmations = tx_confirmations(&st, tx);
        let time = tx_time(tx, first_seen.get(&tx.txid_hex).copied());
        transactions.extend(tx_entries(tx, &label_map, confirmations, time, None));
    }

    // `lastblock` is the hash of the block that currently has `target_confirmations`
    // confirmations: pass it back as the next call's blockhash and any tx with fewer
    // confirmations at this point is reported again rather than missed. When the requested
    // depth predates the wallet's scan range, fall back to the earliest scanned block (a
    // lower cursor only re-reports, never misses); a wallet with nothing scanned yet
    // returns the null hash, Bitcoin Core's own out-of-range edge.
    let lastblock = st
        .fully_scanned
        .and_then(|scanned| scanned.checked_sub(target_conf - 1))
        .and_then(|h| read::block_info_at(&handle.dir, h).ok().flatten())
        .map(|(hash, _)| hash)
        .or_else(|| {
            read::first_scanned_block(&handle.dir)
                .ok()
                .flatten()
                .map(|(_, hash)| hash)
        })
        .unwrap_or_else(|| "0".repeat(64));

    Ok(json!({
        "transactions": transactions,
        "removed": [],
        "lastblock": lastblock,
    }))
}

/// `gettransaction <txid>` - detailed info on one wallet transaction: net `amount`
/// (fee-exclusive, see [`gettransaction_amount`]), per-output `details`, and the raw `hex`
/// (fetched from lightwalletd on demand for received txs only seen as compact outputs).
pub(crate) async fn gettransaction(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let txid = req.require_str(0, "gettransaction requires a txid")?;
    let handle = state.registry.get(wallet)?.clone();
    let st = handle.status();
    let rec = read::get_transaction(&handle.dir, txid)?
        .ok_or_else(|| RpcError::invalid_address_or_key("Invalid or non-wallet transaction id"))?;
    let label_map = labels::all(&handle.dir).unwrap_or_default();

    let details = gettransaction_details(&rec, &label_map);
    let hex_str = gettransaction_hex(&handle, &rec).await;

    let amount = gettransaction_amount(rec.account_balance_delta, rec.fee_paid);
    let confirmations = tx_confirmations(&st, &rec);
    let time = tx_time(&rec, labels::first_seen(&handle.dir, txid).ok().flatten());
    let mut obj = json!({
        "amount": signed_zats_to_value(amount),
        "confirmations": confirmations,
        "txid": rec.txid_hex,
        "bip125-replaceable": "no",
        "details": details,
        "hex": hex_str,
    });
    if let Some(fee) = rec.fee_paid {
        obj["fee"] = signed_zats_to_value(-(fee as i64));
    }
    push_wallet_tx_fields(&mut obj, &rec, time);
    Ok(obj)
}

/// Build `gettransaction.details`: one entry per non-change output and category, sends
/// negative - [`tx_entries`]'s conventions minus the per-tx fields (`confirmations`, `txid`,
/// times), which `gettransaction` carries at the top level instead.
fn gettransaction_details(rec: &read::TxRecord, label_map: &HashMap<String, String>) -> Vec<Value> {
    let mut details = Vec::new();
    for out in &rec.outputs {
        if out.is_change {
            continue;
        }
        let categories = output_categories(out.from_account.is_some(), out.to_account.is_some());
        for category in categories {
            let amount = if *category == "send" {
                -out.value
            } else {
                out.value
            };
            let label = out
                .to_address
                .as_ref()
                .and_then(|a| label_map.get(a).cloned())
                .unwrap_or_default();
            let mut d = json!({
                "address": out.to_address.clone().unwrap_or_default(),
                "category": category,
                "amount": signed_zats_to_value(amount),
                "vout": out.output_index,
                "label": label,
            });
            if *category == "send" {
                d["abandoned"] = json!(rec.expired_unmined);
                if let Some(fee) = rec.fee_paid {
                    d["fee"] = signed_zats_to_value(-(fee as i64));
                }
            }
            push_memo_fields(&mut d, out.memo.as_deref());
            details.push(d);
        }
    }
    details
}

/// `gettransaction.hex`: stored raw bytes for txs we created; otherwise fetch the full tx on
/// demand (received txs are only seen as compact blocks until enhanced). Best-effort - an
/// unreachable upstream yields an empty string, not an error.
async fn gettransaction_hex(handle: &crate::wallet::WalletHandle, rec: &read::TxRecord) -> String {
    match &rec.raw {
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
    }
}

/// Parse one of `listunspent`'s integer depth params with Bitcoin Core's typed-argument
/// strictness (wrong type is a -3, not silently the default).
pub(crate) fn depth_param(v: Option<&Value>, name: &str, default: i64) -> Result<i64, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_i64()
            .ok_or_else(|| RpcError::type_error(format!("{name} must be a number"))),
    }
}

/// Parse `listunspent`'s `addresses` filter: every entry must be a valid address for the
/// network (-5, like Bitcoin Core) and duplicates are rejected (-8). `None` means no filter.
fn addresses_filter(
    v: Option<&Value>,
    network: &crate::network::ZNetwork,
) -> Result<Option<BTreeSet<String>>, RpcError> {
    let arr = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(a)) if a.is_empty() => return Ok(None),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(RpcError::type_error("addresses must be an array")),
    };
    let mut set = BTreeSet::new();
    for entry in arr {
        let s = entry
            .as_str()
            .ok_or_else(|| RpcError::type_error("addresses entries must be strings"))?;
        if !crate::address::validate(network, s).is_valid {
            return Err(RpcError::invalid_address_or_key(format!(
                "Invalid Zcash address: {s}"
            )));
        }
        if !set.insert(s.to_string()) {
            return Err(RpcError::invalid_parameter(format!(
                "Invalid parameter, duplicated address: {s}"
            )));
        }
    }
    Ok(Some(set))
}

/// Shape and filter the `listunspent` response. Each unspent Orchard note is one entry; the
/// (txid, vout) refers to the shielded action that created the note (no transparent
/// scriptPubKey exists) and `address` is the receiving diversified address when the wallet
/// recorded one (change/internal notes report an empty string, which an address filter never
/// matches).
fn unspent_json(
    notes: &[read::UnspentNote],
    st: &SyncStatus,
    minconf: i64,
    maxconf: i64,
    filter: Option<&BTreeSet<String>>,
    include_unsafe: bool,
) -> Vec<Value> {
    notes
        .iter()
        .map(|n| (st.confirmations(n.mined_height), n))
        .filter(|(conf, n)| {
            // Bitcoin Core: confirmed notes and the wallet's *own* unconfirmed change are
            // safe to spend; a foreign note surfaced at 0-conf (minconf=0, fed by the
            // mempool stream) is not.
            let safe = *conf > 0 || n.trusted;
            *conf >= minconf
                && *conf <= maxconf
                && (include_unsafe || safe)
                && filter.is_none_or(|f| n.address.as_ref().is_some_and(|a| f.contains(a)))
        })
        .map(|(conf, n)| {
            json!({
                "txid": n.txid,
                "vout": n.vout,
                "address": n.address.clone().unwrap_or_default(),
                "amount": zats_to_value(n.value),
                "confirmations": conf,
                "spendable": true,
                "solvable": true,
                "safe": conf > 0 || n.trusted,
            })
        })
        .collect()
}

/// `listunspent [minconf] [maxconf] [addresses] [include_unsafe]` - the wallet's unspent
/// Orchard notes in Bitcoin Core's UTXO shape; see [`unspent_json`] for the synthesized
/// `(txid, vout)` convention.
pub(crate) fn listunspent(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let minconf = depth_param(req.param(0), "minconf", 1)?;
    let maxconf = depth_param(req.param(1), "maxconf", 9_999_999)?;
    let handle = state.registry.get(wallet)?;
    let filter = addresses_filter(req.param(2), &handle.network)?;
    let include_unsafe = match req.param(3) {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(RpcError::type_error("include_unsafe must be a boolean")),
    };
    let st = handle.status();
    let notes = read::list_unspent(handle.network, &handle.dir)?;
    Ok(Value::Array(unspent_json(
        &notes,
        &st,
        minconf,
        maxconf,
        filter.as_ref(),
        include_unsafe,
    )))
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

fn build_payment(
    network: &crate::network::ZNetwork,
    privacy: SendPrivacy,
    addr: &str,
    amount: &Value,
    memo_hex: Option<&str>,
) -> Result<Payment, RpcError> {
    let zaddr = crate::address::parse_recipient_on_network(network, addr)?;
    // A recipient without an Orchard receiver pulls the send out of the Orchard pool,
    // revealing the amount on-chain (and the recipient, if transparent). zcashd/Zallet
    // require an explicit AllowRevealed* opt-in for that; zecd's is `[spend]
    // privacy_policy`, which defaults to allowing it.
    if privacy == SendPrivacy::FullPrivacy {
        let receives_orchard = crate::address::decode_on_network(network, addr)
            .is_some_and(|a| crate::address::has_orchard_receiver(&a));
        if !receives_orchard {
            return Err(RpcError::invalid_parameter(format!(
                "Privacy policy FullPrivacy rejects {addr}: it cannot receive in the Orchard \
                 pool, so paying it would reveal the amount on-chain. Set [spend] \
                 privacy_policy = \"AllowRevealedRecipients\" to permit this."
            )));
        }
    }
    let zats = value_to_zats(amount)?;
    // Bitcoin Core rejects sending a zero amount with -3 "Invalid amount" (negative and
    // over-MAX_MONEY amounts are already "Amount out of range" in value_to_zats).
    if zats.into_u64() == 0 {
        return Err(RpcError::type_error("Invalid amount"));
    }
    // Hex-encoded shielded memo, zcashd's z_sendmany convention (and error messages).
    let memo = match memo_hex {
        None => None,
        Some(h) => {
            let bytes = hex::decode(h).map_err(|_| {
                RpcError::invalid_parameter(
                    "Invalid parameter, expected memo data in hexadecimal format.",
                )
            })?;
            Some(MemoBytes::from_bytes(&bytes).map_err(|_| {
                RpcError::invalid_parameter(
                    "Invalid parameter, memo is longer than the maximum allowed 512 bytes.",
                )
            })?)
        }
    };
    Payment::new(zaddr, Some(zats), memo, None, None, vec![]).map_err(|_| {
        // The only constructible failure here: a memo paired with a memo-less (transparent)
        // recipient (zero-valued transparent outputs were rejected above).
        RpcError::invalid_parameter("Memo cannot be used with a transparent recipient")
    })
}

/// Parse a `verbose` flag with Bitcoin Core's strictness (boolean or omitted, else -3).
fn verbose_param(v: Option<&Value>) -> Result<bool, RpcError> {
    match v {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RpcError::type_error("verbose must be a boolean")),
    }
}

/// Shape a send result: bare txid by default; `verbose` adds `fee_reason`, which for zecd is
/// always the ZIP-317 conventional fee (there is no estimator to report).
fn send_result(txid: String, verbose: bool) -> Value {
    if verbose {
        json!({ "txid": txid, "fee_reason": "ZIP 317" })
    } else {
        Value::String(txid)
    }
}

/// `sendtoaddress <address> <amount> [...] [verbose] [memo]` - pay one recipient from the
/// Orchard pool. Sends serialize through the wallet actor (no double-spends under
/// concurrency); fee is always ZIP-317. The trailing `memo` param is a zecd extension.
pub(crate) async fn sendtoaddress(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let addr = req.require_str(0, "sendtoaddress requires an address")?;
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
    let verbose = verbose_param(req.param(10))?;
    // Param 11 (memo) is a zecd extension beyond Bitcoin Core's argument list: a
    // hex-encoded ZIP-302 memo for the (shielded) recipient, as in zcashd's z_sendmany.
    let memo = match req.param(11) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return Err(RpcError::type_error("memo must be a hex string")),
    };
    let handle = state.registry.get(wallet)?.clone();
    let payment = build_payment(
        &handle.network,
        state.config.spend.privacy,
        addr,
        amount,
        memo,
    )?;
    let request = TransactionRequest::new(vec![payment])
        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e}")))?;
    let txid = handle.send(request, None).await?;
    Ok(send_result(txid.to_string(), verbose))
}

/// `sendmany "" {address: amount, ...} [...]` - pay several recipients in one transaction
/// (one ZIP-317 fee, one anchor).
pub(crate) async fn sendmany(
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
    let verbose = verbose_param(req.param(9))?;
    let handle = state.registry.get(wallet)?.clone();
    let mut payments = Vec::new();
    for (addr, amount) in recipients {
        payments.push(build_payment(
            &handle.network,
            state.config.spend.privacy,
            addr,
            amount,
            None,
        )?);
    }
    if payments.is_empty() {
        return Err(RpcError::invalid_params(
            "sendmany requires at least one recipient",
        ));
    }
    let request = TransactionRequest::new(payments)
        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e}")))?;
    let txid = handle.send(request, None).await?;
    Ok(send_result(txid.to_string(), verbose))
}

// ---- Asynchronous operations (zcashd-style `z_sendmany` + `z_getoperation*`) ----

/// Map a zcashd `privacyPolicy` string onto zecd's two-variant [`SendPrivacy`]. zecd only ever
/// spends shielded Orchard notes, so the one privacy axis it can act on is whether a recipient
/// *without* an Orchard receiver (transparent / Sapling-only) is permitted - zcashd's other
/// policies differ only in sender-side leakage, which has no analog here. Omitted or
/// `LegacyCompat` fall back to the wallet's configured `[spend] privacy_policy`; an unknown
/// value is `-8`.
fn privacy_from_policy(s: Option<&str>, default: SendPrivacy) -> Result<SendPrivacy, RpcError> {
    match s {
        None | Some("LegacyCompat") => Ok(default),
        Some("FullPrivacy") => Ok(SendPrivacy::FullPrivacy),
        Some("AllowRevealedAmounts")
        | Some("AllowRevealedRecipients")
        | Some("AllowRevealedSenders")
        | Some("AllowFullyTransparent")
        | Some("AllowLinkingAccountAddresses")
        | Some("NoPrivacy") => Ok(SendPrivacy::AllowRevealedRecipients),
        Some(other) => Err(RpcError::invalid_parameter(format!(
            "Unknown privacy policy: {other}"
        ))),
    }
}

/// Parse the optional `["opid-...", ...]` argument shared by `z_getoperationstatus` and
/// `z_getoperationresult`. Absent/null → `None` (all of the wallet's operations); otherwise an
/// array of opid strings - a malformed opid or non-string element is `-8`.
fn parse_opid_filter(req: &RpcRequest, i: usize) -> Result<Option<Vec<OperationId>>, RpcError> {
    match req.param(i) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(arr)) => {
            let mut ids = Vec::with_capacity(arr.len());
            for v in arr {
                let s = v.as_str().ok_or_else(|| {
                    RpcError::invalid_parameter("Invalid operation ID, expected a string")
                })?;
                ids.push(s.parse::<OperationId>()?);
            }
            Ok(Some(ids))
        }
        Some(_) => Err(RpcError::invalid_parameter(
            "Invalid parameter, expected an array of operation ids",
        )),
    }
}

/// `z_sendmany "<fromaddress>" [{"address":..,"amount":..,"memo":..}, ..] (minconf) (fee) (privacyPolicy)`
/// zcashd's asynchronous shielded send. Returns an operation id (`opid-...`) immediately; the
/// transaction is proposed, proved, and broadcast on a background task whose status/result are
/// fetched with `z_getoperationstatus`/`z_getoperationresult`. zecd spends from its single
/// Orchard account, so `fromaddress` must be one of this wallet's own addresses. Fees are
/// ZIP-317 (an explicit `fee` is `-8`); `minconf` overrides note-selection depth for this send.
pub(crate) fn z_sendmany(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?.clone();

    // fromaddress (arg 0): reject ANY_TADDR (zecd has no transparent source to select) and
    // validate that the address belongs to this wallet's account, mirroring Zallet's
    // `get_account_for_address`.
    let fromaddress = req.require_str(0, "z_sendmany requires a fromaddress")?;
    if fromaddress == "ANY_TADDR" {
        return Err(RpcError::invalid_address_or_key(
            "Invalid from address: ANY_TADDR is not supported (zecd spends from its Orchard \
             account)",
        ));
    }
    if crate::address::decode_on_network(&handle.network, fromaddress).is_none() {
        return Err(RpcError::invalid_address_or_key(
            "Invalid from address: should be a taddr, zaddr, or unified address",
        ));
    }
    if !read::is_mine(handle.network, &handle.dir, fromaddress) {
        return Err(RpcError::invalid_address_or_key(
            "Invalid from address, no payment source found for address.",
        ));
    }

    // amounts (arg 1): a non-empty array of {address, amount, memo?} objects (zcashd's shape,
    // not Bitcoin Core's `{addr: amount}` map).
    let outputs = req
        .param(1)
        .and_then(|v| v.as_array())
        .ok_or_else(|| RpcError::invalid_parameter("Invalid parameter, expected amounts array"))?;
    if outputs.is_empty() {
        return Err(RpcError::invalid_parameter(
            "Invalid parameter, amounts array is empty.",
        ));
    }

    // fee (arg 3): ZIP-317 only - an explicit fee is rejected, never silently applied.
    if req.param(3).is_some_and(param_engaged) {
        return Err(RpcError::invalid_parameter(
            "fee is not supported (fees are ZIP-317, computed by the wallet)",
        ));
    }

    // privacyPolicy (arg 4): per-call override of `[spend] privacy_policy`.
    let privacy = privacy_from_policy(
        req.param(4).and_then(|v| v.as_str()),
        state.config.spend.privacy,
    )?;

    // minconf (arg 2): honored - mapped onto a per-call symmetric confirmations policy
    // (default = the wallet's configured policy when omitted).
    let policy = minconf_policy(req.param(2), handle.confirmations)?;

    // Build the payments, rejecting unknown keys and duplicate recipients (zcashd does both).
    let mut seen = BTreeSet::new();
    let mut payments = Vec::with_capacity(outputs.len());
    for out in outputs {
        let obj = out
            .as_object()
            .ok_or_else(|| RpcError::invalid_parameter("amounts entry must be an object"))?;
        for key in obj.keys() {
            if !matches!(key.as_str(), "address" | "amount" | "memo") {
                return Err(RpcError::invalid_parameter(format!(
                    "Invalid parameter, unrecognized key: {key}"
                )));
            }
        }
        let addr = obj
            .get("address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::invalid_parameter("amounts entry requires an address"))?;
        let amount = obj
            .get("amount")
            .ok_or_else(|| RpcError::invalid_parameter("amounts entry requires an amount"))?;
        let memo = match obj.get("memo") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(RpcError::type_error("memo must be a hex string")),
        };
        if !seen.insert(addr.to_string()) {
            return Err(RpcError::invalid_parameter(format!(
                "Invalid parameter, duplicated recipient address: {addr}"
            )));
        }
        payments.push(build_payment(&handle.network, privacy, addr, amount, memo)?);
    }

    let request = TransactionRequest::new(payments)
        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e}")))?;

    // Echo the call context (zcashd's `method`/`params` on the status object).
    let context = ContextInfo::new(
        "z_sendmany",
        json!({
            "fromaddress": fromaddress,
            "amounts": Value::Array(outputs.clone()),
            "minconf": req.param(2).cloned().unwrap_or_else(|| json!(1)),
        }),
    );

    // Spawn the send on a background task and return the opid immediately. Every send error
    // (including `-6` insufficient funds) surfaces later via the operation's `error`, never as
    // a synchronous error here. The send still funnels through the single-writer actor, so the
    // no-double-spend invariant holds exactly as for the synchronous sends.
    let send_handle = handle.clone();
    let op = AsyncOperation::new(Some(context), async move {
        let txid = send_handle.send(request, Some(policy)).await?;
        Ok::<Value, RpcError>(json!({ "txid": txid.to_string() }))
    });
    let opid = state.operations.insert(&handle.name, op);
    Ok(Value::String(opid))
}

/// `z_getoperationstatus ([opid, ...])` - status objects for the wallet's async operations
/// (all of them when no array is given). Non-destructive; well-formed-but-unknown ids are
/// silently omitted, a malformed id is `-8`.
pub(crate) fn z_getoperationstatus(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let ids = parse_opid_filter(req, 0)?;
    let statuses = state.operations.status(&handle.name, ids.as_deref());
    serde_json::to_value(statuses).map_err(|e| RpcError::misc(e.to_string()))
}

/// `z_getoperationresult ([opid, ...])` - like `z_getoperationstatus`, but returns only
/// *finished* operations (success/failed/cancelled) and removes them from memory.
pub(crate) fn z_getoperationresult(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let ids = parse_opid_filter(req, 0)?;
    let statuses = state.operations.take_results(&handle.name, ids.as_deref());
    serde_json::to_value(statuses).map_err(|e| RpcError::misc(e.to_string()))
}

/// `z_listoperationids (["status"])` - the opid strings of the wallet's operations, optionally
/// filtered by status string (`queued`/`executing`/`success`/`failed`/`cancelled`); an
/// unrecognized filter returns an empty list.
pub(crate) fn z_listoperationids(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?;
    let filter = req.param(0).and_then(|v| v.as_str());
    Ok(json!(state.operations.list_ids(&handle.name, filter)))
}

/// Bitcoin Core clamps the unlock timeout to this many seconds (~3.17 years); larger values
/// are silently reduced rather than rejected.
const MAX_UNLOCK_TIMEOUT_SECS: i64 = 100_000_000;

/// `walletpassphrase <passphrase> <timeout>` - decrypt the seed into memory for `timeout`
/// seconds (auto-relock after). Wrong passphrase is `-14`; an unencrypted wallet is `-15`.
pub(crate) async fn walletpassphrase(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let passphrase = req.require_str(0, "walletpassphrase requires a passphrase")?;
    // Timeout (seconds) is required and must be a non-negative integer; huge values are clamped.
    let timeout = req.param(1).and_then(|v| v.as_i64()).ok_or_else(|| {
        RpcError::invalid_parameter("walletpassphrase requires an integer timeout (seconds)")
    })?;
    if timeout < 0 {
        return Err(RpcError::invalid_parameter("Timeout cannot be negative."));
    }
    if passphrase.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    let timeout = timeout.min(MAX_UNLOCK_TIMEOUT_SECS);
    let handle = state.registry.get(wallet)?.clone();
    handle
        .unlock(Passphrase::from(passphrase.to_owned()), timeout)
        .await?;
    Ok(Value::Null)
}

/// `walletlock` - drop the decrypted seed immediately; sends then fail with `-13` until the
/// next `walletpassphrase`.
pub(crate) async fn walletlock(state: &AppState, wallet: Option<&str>) -> Result<Value, RpcError> {
    let handle = state.registry.get(wallet)?.clone();
    handle.lock().await?;
    Ok(Value::Null)
}

/// `encryptwallet <passphrase>` - wrap the age-encrypted mnemonic under a passphrase; the
/// wallet locks immediately afterwards.
pub(crate) async fn encryptwallet(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let passphrase = req.require_str(0, "encryptwallet requires a passphrase")?;
    if passphrase.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    let handle = state.registry.get(wallet)?.clone();
    handle
        .encrypt_wallet(Passphrase::from(passphrase.to_owned()))
        .await?;
    // Unlike Bitcoin Core, the mnemonic/seed is unchanged (no new backup needed) - only the
    // at-rest wrapping changed, so the wallet is now locked and needs walletpassphrase.
    Ok(Value::String(
        "wallet encrypted; the mnemonic is now passphrase-protected. \
         Call walletpassphrase to unlock before sending."
            .to_string(),
    ))
}

/// `walletpassphrasechange <old> <new>` - re-wrap the seed under a new passphrase (the
/// old one must verify; `-14` otherwise).
pub(crate) async fn walletpassphrasechange(
    state: &AppState,
    wallet: Option<&str>,
    req: &RpcRequest,
) -> Result<Value, RpcError> {
    let old = req.require_str(0, "walletpassphrasechange requires the old passphrase")?;
    let new = req.require_str(1, "walletpassphrasechange requires the new passphrase")?;
    if new.is_empty() {
        return Err(RpcError::invalid_parameter("passphrase cannot be empty"));
    }
    let handle = state.registry.get(wallet)?.clone();
    handle
        .change_passphrase(
            Passphrase::from(old.to_owned()),
            Passphrase::from(new.to_owned()),
        )
        .await?;
    Ok(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pools::Pool;
    use crate::wallet::read::{TxOutputRecord, TxRecord};

    #[test]
    fn receiver_tokens_default_to_none() {
        // Empty / unified / default all mean "use the wallet's configured default_receivers".
        assert!(parse_receiver_tokens(None).unwrap().is_none());
        assert!(parse_receiver_tokens(Some("")).unwrap().is_none());
        assert!(parse_receiver_tokens(Some("  ")).unwrap().is_none());
        assert!(parse_receiver_tokens(Some("unified")).unwrap().is_none());
        assert!(parse_receiver_tokens(Some("UNIFIED")).unwrap().is_none());
        assert!(parse_receiver_tokens(Some("default")).unwrap().is_none());
    }

    #[test]
    fn receiver_tokens_single_and_list() {
        let one = parse_receiver_tokens(Some("sapling")).unwrap().unwrap();
        assert!(one.contains(Pool::Sapling) && !one.contains(Pool::Orchard));

        let both = parse_receiver_tokens(Some("sapling,orchard"))
            .unwrap()
            .unwrap();
        assert!(both.contains(Pool::Sapling) && both.contains(Pool::Orchard));

        // Whitespace around list members is tolerated.
        let spaced = parse_receiver_tokens(Some(" orchard , sapling "))
            .unwrap()
            .unwrap();
        assert!(spaced.contains(Pool::Sapling) && spaced.contains(Pool::Orchard));
    }

    #[test]
    fn receiver_tokens_unknown_is_invalid_address_or_key() {
        let err = parse_receiver_tokens(Some("bech32")).unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
        // A list with one bad member is rejected too.
        let err = parse_receiver_tokens(Some("orchard,bogus")).unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
    }

    #[test]
    fn requested_receivers_must_be_subset_of_enabled() {
        // The enablement check (a `-8`) is what getnewaddress applies once it has the handle.
        let enabled = crate::pools::PoolSet::single(Pool::Orchard);
        let requested = parse_receiver_tokens(Some("sapling")).unwrap().unwrap();
        assert!(!requested.is_subset_of(&enabled));
        let ok = parse_receiver_tokens(Some("orchard")).unwrap().unwrap();
        assert!(ok.is_subset_of(&enabled));
    }

    #[test]
    fn privacy_from_policy_maps_every_case() {
        use SendPrivacy::*;
        // Omitted and LegacyCompat fall back to the configured default (both directions).
        assert_eq!(privacy_from_policy(None, FullPrivacy).unwrap(), FullPrivacy);
        assert_eq!(
            privacy_from_policy(None, AllowRevealedRecipients).unwrap(),
            AllowRevealedRecipients
        );
        assert_eq!(
            privacy_from_policy(Some("LegacyCompat"), FullPrivacy).unwrap(),
            FullPrivacy
        );
        // Explicit FullPrivacy.
        assert_eq!(
            privacy_from_policy(Some("FullPrivacy"), AllowRevealedRecipients).unwrap(),
            FullPrivacy
        );
        // Every weaker-or-equal zcashd policy maps onto AllowRevealedRecipients.
        for p in [
            "AllowRevealedAmounts",
            "AllowRevealedRecipients",
            "AllowRevealedSenders",
            "AllowFullyTransparent",
            "AllowLinkingAccountAddresses",
            "NoPrivacy",
        ] {
            assert_eq!(
                privacy_from_policy(Some(p), FullPrivacy).unwrap(),
                AllowRevealedRecipients,
                "{p}"
            );
        }
        // An unknown policy is -8.
        let err = privacy_from_policy(Some("nope"), FullPrivacy).unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_INVALID_PARAMETER);
    }

    #[test]
    fn parse_opid_filter_handles_all_shapes() {
        use crate::error::codes;
        let req = |params: Vec<Value>| RpcRequest {
            id: Value::Null,
            method: "z_getoperationstatus".into(),
            params,
        };
        // Absent or null -> no filter (all of the wallet's ops).
        assert!(parse_opid_filter(&req(vec![]), 0).unwrap().is_none());
        assert!(parse_opid_filter(&req(vec![Value::Null]), 0)
            .unwrap()
            .is_none());
        // A well-formed array parses.
        let ids = parse_opid_filter(
            &req(vec![json!(["opid-00000000-0000-0000-0000-000000000000"])]),
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(ids.len(), 1);
        // A malformed opid, a non-string element, and a non-array param are all -8.
        for bad in [json!(["not-an-opid"]), json!([123]), json!("notarray")] {
            let err = parse_opid_filter(&req(vec![bad]), 0).unwrap_err();
            assert_eq!(err.code, codes::RPC_INVALID_PARAMETER);
        }
    }

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
            memo: None,
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
            block_time: mined.map(|_| 1_700_000_000),
            expired_unmined: expired,
            tx_index: mined.map(|_| 2),
            block_hash: mined.map(|_| "cd".repeat(32)),
            created_time: None,
            outputs,
            raw: None,
        }
    }

    #[test]
    fn minconf_policy_maps_bitcoind_semantics() {
        // Omitted/null: the wallet's configured policy (ZIP-315 3/10 unless overridden in
        // `[spend]`), i.e. spendability.
        for v in [None, Some(&Value::Null)] {
            let p = minconf_policy(v, ConfirmationsPolicy::default()).unwrap();
            assert_eq!((p.trusted().get(), p.untrusted().get()), (3, 10));
        }
        // An explicit minconf overrides both bounds symmetrically. 0 (Bitcoin Core's
        // default) is served as 1: shielded notes are never spendable unmined.
        for (arg, want) in [(0, 1), (1, 1), (6, 6)] {
            let p = minconf_policy(Some(&json!(arg)), ConfirmationsPolicy::default()).unwrap();
            assert_eq!((p.trusted().get(), p.untrusted().get()), (want, want));
        }
        // Wrong type is a -3, like Bitcoin Core's typed argument parsing.
        let e = minconf_policy(Some(&json!("six")), ConfirmationsPolicy::default()).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
    }

    #[test]
    fn getbalance_dummy_must_be_star() {
        assert!(check_balance_dummy(None).is_ok());
        assert!(check_balance_dummy(Some(&Value::Null)).is_ok());
        assert!(check_balance_dummy(Some(&json!("*"))).is_ok());
        let e = check_balance_dummy(Some(&json!("account1"))).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_METHOD_DEPRECATED);
        let e = check_balance_dummy(Some(&json!(7))).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
    }

    fn note(
        conf_height: Option<u32>,
        value: u64,
        trusted: bool,
        address: Option<&str>,
    ) -> read::UnspentNote {
        read::UnspentNote {
            txid: "ab".repeat(32),
            vout: 0,
            value,
            mined_height: conf_height,
            trusted,
            address: address.map(str::to_string),
        }
    }

    #[test]
    fn listunspent_filters_depth_safety_and_addresses() {
        let st = status(100); // fully_scanned 100
        let notes = vec![
            note(Some(91), 10, false, Some("addr-a")),  // 10 conf
            note(Some(100), 20, false, Some("addr-b")), // 1 conf
            note(None, 30, true, None),                 // own unconfirmed change: safe
            note(None, 40, false, Some("addr-a")),      // foreign 0-conf: unsafe
        ];
        // Defaults (minconf 1): the two mined notes.
        let r = unspent_json(&notes, &st, 1, 9_999_999, None, true);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["address"], json!("addr-a"));
        assert_eq!(r[0]["safe"], json!(true));
        // minconf 0 picks up both unconfirmed notes; include_unsafe=false drops the
        // foreign one but keeps our own change.
        assert_eq!(unspent_json(&notes, &st, 0, 9_999_999, None, true).len(), 4);
        let safe_only = unspent_json(&notes, &st, 0, 9_999_999, None, false);
        assert_eq!(safe_only.len(), 3);
        assert!(safe_only.iter().all(|e| e["safe"] == json!(true)));
        // maxconf bounds the depth from above.
        assert_eq!(unspent_json(&notes, &st, 1, 5, None, true).len(), 1);
        // The address filter matches the recorded receiving address; notes without one
        // (change) never match.
        let f: BTreeSet<String> = ["addr-a".to_string()].into();
        let r = unspent_json(&notes, &st, 0, 9_999_999, Some(&f), true);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|e| e["address"] == json!("addr-a")));
    }

    #[test]
    fn listunspent_param_parsing() {
        // Depth params: strict typing, defaults on omission.
        assert_eq!(depth_param(None, "minconf", 1).unwrap(), 1);
        assert_eq!(depth_param(Some(&json!(6)), "minconf", 1).unwrap(), 6);
        let e = depth_param(Some(&json!("6")), "minconf", 1).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);

        // Address filter: a valid testnet UA passes, duplicates are -8, garbage is -5,
        // non-arrays are -3, and empty/omitted means no filter.
        let net = crate::network::ZNetwork::Test;
        let ua = "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";
        assert!(addresses_filter(None, &net).unwrap().is_none());
        assert!(addresses_filter(Some(&json!([])), &net).unwrap().is_none());
        let f = addresses_filter(Some(&json!([ua])), &net).unwrap().unwrap();
        assert!(f.contains(ua));
        let e = addresses_filter(Some(&json!([ua, ua])), &net).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        let e = addresses_filter(Some(&json!(["nonsense"])), &net).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);
        let e = addresses_filter(Some(&json!("addr")), &net).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
    }

    #[test]
    fn send_params_match_bitcoind() {
        let net = crate::network::ZNetwork::Test;
        let revealed = SendPrivacy::AllowRevealedRecipients;
        let ua = "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";
        // Zero amounts are a -3 "Invalid amount" like Bitcoin Core; positive ones build.
        let e = build_payment(&net, revealed, ua, &json!(0), None).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_TYPE_ERROR);
        assert!(e.message.contains("Invalid amount"), "{}", e.message);
        assert!(build_payment(&net, revealed, ua, &json!(0.1), None).is_ok());

        // verbose: bare txid by default, {txid, fee_reason} object when set, -3 on junk.
        assert!(!verbose_param(None).unwrap());
        assert!(verbose_param(Some(&json!(true))).unwrap());
        assert_eq!(
            verbose_param(Some(&json!("yes"))).unwrap_err().code,
            crate::error::codes::RPC_TYPE_ERROR
        );
        assert_eq!(send_result("ab".repeat(32), false), json!("ab".repeat(32)));
        let v = send_result("ab".repeat(32), true);
        assert_eq!(v["txid"], json!("ab".repeat(32)));
        assert_eq!(v["fee_reason"], json!("ZIP 317"));
    }

    #[test]
    fn memo_fields_ride_on_entries_with_memos() {
        // A text memo yields both hex and decoded forms.
        let mut t = tx(
            Some(50),
            false,
            None,
            vec![out(false, true, 5, Some("ua"), false)],
        );
        t.outputs[0].memo = Some(b"invoice 42".to_vec());
        let e = tx_entries(&t, &HashMap::new(), 1, 0, None);
        assert_eq!(e[0]["memo"], json!(hex::encode(b"invoice 42")));
        assert_eq!(e[0]["memoStr"], json!("invoice 42"));

        // Empty (0xF6) and absent memos add nothing; an arbitrary-data memo (first byte
        // 0xFF) is hex-only.
        t.outputs[0].memo = Some(vec![0xF6]);
        let e = tx_entries(&t, &HashMap::new(), 1, 0, None);
        assert!(e[0].get("memo").is_none() && e[0].get("memoStr").is_none());
        t.outputs[0].memo = Some(vec![0xFF, 0x01, 0x02]);
        let e = tx_entries(&t, &HashMap::new(), 1, 0, None);
        assert_eq!(e[0]["memo"], json!("ff0102"));
        assert!(e[0].get("memoStr").is_none());
    }

    #[test]
    fn sendtoaddress_memo_param_builds_and_validates() {
        let net = crate::network::ZNetwork::Test;
        let p = SendPrivacy::AllowRevealedRecipients;
        let ua = "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";
        // A hex memo to a shielded recipient builds.
        assert!(build_payment(&net, p, ua, &json!(0.1), Some("f00f")).is_ok());
        // Bad hex and oversized memos are -8 with zcashd's messages.
        let e = build_payment(&net, p, ua, &json!(0.1), Some("xyz")).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(e.message.contains("hexadecimal"), "{}", e.message);
        let e = build_payment(&net, p, ua, &json!(0.1), Some(&"ab".repeat(513))).unwrap_err();
        assert!(e.message.contains("512"), "{}", e.message);
        // A memo to a transparent recipient is rejected.
        use zcash_keys::encoding::AddressCodec as _;
        let taddr =
            zcash_transparent::address::TransparentAddress::PublicKeyHash([0u8; 20]).encode(&net);
        let e = build_payment(&net, p, &taddr, &json!(0.1), Some("f00f")).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(e.message.contains("transparent"), "{}", e.message);
    }

    #[test]
    fn full_privacy_rejects_non_orchard_recipients() {
        use zcash_keys::encoding::AddressCodec as _;
        let net = crate::network::ZNetwork::Test;
        let ua = "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";
        let taddr =
            zcash_transparent::address::TransparentAddress::PublicKeyHash([0u8; 20]).encode(&net);

        // FullPrivacy: an Orchard-receiving UA passes; a transparent recipient is -8 with a
        // self-diagnosing message; the default policy allows both.
        assert!(build_payment(&net, SendPrivacy::FullPrivacy, ua, &json!(0.1), None).is_ok());
        let e =
            build_payment(&net, SendPrivacy::FullPrivacy, &taddr, &json!(0.1), None).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_PARAMETER);
        assert!(e.message.contains("privacy_policy"), "{}", e.message);
        assert!(build_payment(
            &net,
            SendPrivacy::AllowRevealedRecipients,
            &taddr,
            &json!(0.1),
            None
        )
        .is_ok());
    }

    #[test]
    fn getaddressinfo_shape_matches_bitcoind() {
        use crate::address::Validation;
        // Invalid addresses are a -5 error, not an isvalid:false body.
        let invalid = Validation {
            is_valid: false,
            is_orchard: false,
            receiver_types: Vec::new(),
            script_pub_key: None,
            is_script: false,
        };
        let e = addressinfo_json(invalid, "nonsense", false, None).unwrap_err();
        assert_eq!(e.code, crate::error::codes::RPC_INVALID_ADDRESS_OR_KEY);

        // Valid: Bitcoin Core's field set, without an isvalid field. The shape is identical
        // on watch-only (UFVK) wallets: master's `iswatchonly` is deprecated/always-false
        // and `solvable` ignores the lack of private keys, so neither field varies - the
        // watch-only signal is `getwalletinfo.private_keys_enabled`.
        let valid = Validation {
            is_valid: true,
            is_orchard: true,
            receiver_types: vec!["orchard"],
            script_pub_key: None,
            is_script: false,
        };
        let o = addressinfo_json(valid, "utest1abc", true, Some("hot".into())).unwrap();
        assert!(o.get("isvalid").is_none());
        assert_eq!(o["address"], json!("utest1abc"));
        assert_eq!(o["ismine"], json!(true));
        assert_eq!(o["solvable"], json!(true));
        assert_eq!(o["iswatchonly"], json!(false));
        assert_eq!(o["iswitness"], json!(false));
        assert_eq!(o["scriptPubKey"], json!(""));
        // Extension fields: the address's receiver verdicts.
        assert_eq!(o["isvalid_orchard"], json!(true));
        assert_eq!(o["receiver_types"], json!(["orchard"]));
        assert_eq!(o["labels"], json!(["hot"]));
    }

    #[test]
    fn receive_entry_shape() {
        let t = tx(
            Some(100),
            false,
            None,
            vec![out(false, true, 150_000_000, Some("ua"), false)],
        );
        let st = status(102);
        let e = tx_entries(
            &t,
            &HashMap::new(),
            tx_confirmations(&st, &t),
            tx_time(&t, None),
            None,
        );
        assert_eq!(e.len(), 1);
        assert_eq!(e[0]["category"], "receive");
        assert_eq!(e[0]["amount"].to_string(), "1.50000000");
        assert_eq!(e[0]["confirmations"], json!(3));
        // Mined: Bitcoin Core's block fields, and no `trusted` (that rides on unmined txs).
        assert_eq!(e[0]["blockheight"], json!(100));
        assert_eq!(e[0]["blockhash"], json!("cd".repeat(32)));
        assert_eq!(e[0]["blockindex"], json!(2));
        assert_eq!(e[0]["blocktime"], json!(1_700_000_000));
        assert_eq!(e[0]["walletconflicts"], json!([]));
        assert_eq!(e[0]["time"], json!(1_700_000_000));
        assert_eq!(e[0]["timereceived"], json!(1_700_000_000));
        assert!(e[0].get("trusted").is_none());
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
        let e = tx_entries(&t, &HashMap::new(), 1, tx_time(&t, None), None);
        assert_eq!(e[0]["category"], "send");
        assert_eq!(e[0]["amount"].to_string(), "-1.50000000");
        assert_eq!(e[0]["fee"].to_string(), "-0.00010000");
        assert_eq!(e[0]["abandoned"], json!(false));
    }

    #[test]
    fn change_is_skipped_and_self_transfers_pair_up() {
        // Change outputs never produce entries.
        let t = tx(
            Some(50),
            false,
            None,
            vec![out(true, true, 1, Some("self"), true)],
        );
        assert!(tx_entries(&t, &HashMap::new(), 1, 0, None).is_empty());

        // A self-transfer (from us, to us, not change) is Bitcoin Core's send + receive
        // pair: same address/vout, debit then credit, abandoned/fee on the send only.
        let t = tx(
            Some(50),
            false,
            Some(10_000),
            vec![out(true, true, 200, Some("self"), false)],
        );
        let e = tx_entries(&t, &HashMap::new(), 1, 0, None);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["category"], "send");
        assert_eq!(e[0]["amount"].to_string(), "-0.00000200");
        assert_eq!(e[0]["fee"].to_string(), "-0.00010000");
        assert_eq!(e[0]["abandoned"], json!(false));
        assert_eq!(e[1]["category"], "receive");
        assert_eq!(e[1]["amount"].to_string(), "0.00000200");
        assert!(e[1].get("abandoned").is_none());
        assert_eq!(e[0]["address"], e[1]["address"]);
        assert_eq!(e[0]["vout"], e[1]["vout"]);
    }

    #[test]
    fn expired_tx_is_conflicted_and_abandoned() {
        let mut t = tx(
            None,
            true,
            Some(10_000),
            vec![out(true, false, 5, Some("dest"), false)],
        );
        t.account_balance_delta = -10_005;
        let st = status(100);
        let conf = tx_confirmations(&st, &t);
        assert_eq!(conf, -1);
        let e = tx_entries(&t, &HashMap::new(), conf, tx_time(&t, None), None);
        assert_eq!(e[0]["confirmations"], json!(-1));
        assert_eq!(e[0]["abandoned"], json!(true));
        // Expired txs can never be mined, so they are not trusted even though we authored
        // them; mined-only block fields stay absent.
        assert_eq!(e[0]["trusted"], json!(false));
        assert!(e[0].get("blockhash").is_none());
        assert!(e[0].get("blocktime").is_none());
    }

    #[test]
    fn unmined_own_tx_is_trusted_with_first_seen_time() {
        let mut t = tx(
            None,
            false,
            Some(10_000),
            vec![out(true, false, 5, Some("dest"), false)],
        );
        t.account_balance_delta = -10_005;
        let e = tx_entries(
            &t,
            &HashMap::new(),
            0,
            tx_time(&t, Some(1_700_000_123)),
            None,
        );
        assert_eq!(e[0]["trusted"], json!(true));
        assert_eq!(e[0]["time"], json!(1_700_000_123));
        assert_eq!(e[0]["timereceived"], json!(1_700_000_123));
        // A foreign unmined receive is untrusted (Bitcoin Core: not our mempool tx).
        let f = tx(
            None,
            false,
            None,
            vec![out(false, true, 5, Some("ua"), false)],
        );
        let e = tx_entries(&f, &HashMap::new(), 0, tx_time(&f, None), None);
        assert_eq!(e[0]["trusted"], json!(false));
    }

    #[test]
    fn tx_time_falls_back_block_then_first_seen_then_created() {
        let mined = tx(Some(10), false, None, vec![]);
        assert_eq!(tx_time(&mined, Some(5)), 1_700_000_000); // block time wins once mined
        let mut unmined = tx(None, false, None, vec![]);
        unmined.created_time = Some(42);
        assert_eq!(tx_time(&unmined, Some(7)), 7); // first-seen (mempool stream) next
        assert_eq!(tx_time(&unmined, None), 42); // wallet-created timestamp last
        unmined.created_time = None;
        assert_eq!(tx_time(&unmined, None), 0);
    }

    #[test]
    fn label_filter_keeps_only_matches() {
        let mut labels = HashMap::new();
        labels.insert("dest".to_string(), "alice".to_string());
        let t = tx(
            Some(50),
            false,
            None,
            vec![out(false, true, 5, Some("dest"), false)],
        );
        assert_eq!(tx_entries(&t, &labels, 1, 0, Some("alice")).len(), 1);
        assert!(tx_entries(&t, &labels, 1, 0, Some("bob")).is_empty());
        assert_eq!(tx_entries(&t, &labels, 1, 0, None).len(), 1);
    }

    #[test]
    fn received_by_address_groups_and_respects_minconf() {
        let st = status(100);
        let txs = vec![
            tx(
                Some(100),
                false,
                None,
                vec![out(false, true, 100, Some("a"), false)],
            ), // 1 conf
            tx(
                Some(91),
                false,
                None,
                vec![out(false, true, 50, Some("a"), false)],
            ), // 10 conf
            tx(
                None,
                false,
                None,
                vec![out(false, true, 7, Some("a"), false)],
            ), // 0 conf
            tx(
                None,
                true,
                None,
                vec![out(false, true, 9, Some("a"), false)],
            ), // expired: -1 conf
            tx(
                Some(100),
                false,
                None,
                vec![out(true, true, 11, Some("a"), true)],
            ), // change: skipped
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
            tx(
                Some(91),
                false,
                None,
                vec![out(false, true, 100, Some("a1"), false)],
            ),
            tx(
                Some(95),
                false,
                None,
                vec![out(false, true, 50, Some("a2"), false)],
            ),
            tx(
                Some(100),
                false,
                None,
                vec![out(false, true, 7, Some("b"), false)],
            ),
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
        assert_eq!(
            gettransaction_amount(-150_010_000, Some(10_000)),
            -150_000_000
        );
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

    /// Build a `TxRecord` with a distinct txid byte and a list of `(from, to, value,
    /// is_change, output_index)` outputs - enough to make per-tx and within-tx ordering
    /// observable in the windowing tests.
    fn tx_with(
        id: u8,
        mined: Option<u32>,
        expired: bool,
        outs: &[(bool, bool, i64, bool, u32)],
    ) -> TxRecord {
        let outputs = outs
            .iter()
            .map(|&(from, to, value, is_change, idx)| {
                let mut o = out(from, to, value, Some("addr"), is_change);
                o.output_index = idx;
                o
            })
            .collect();
        TxRecord {
            mined_height: mined,
            txid_hex: format!("{id:02x}").repeat(32),
            expiry_height: None,
            account_balance_delta: 0,
            fee_paid: Some(1_000),
            sent_note_count: 0,
            received_note_count: 0,
            block_time: mined.map(|h| 1_700_000_000 + i64::from(h)),
            expired_unmined: expired,
            tx_index: mined.map(|_| 1),
            block_hash: mined.map(|_| "ee".repeat(32)),
            created_time: None,
            outputs,
            raw: None,
        }
    }

    /// The NEW newest-first windowing (`window_history_from_txs`) must produce byte-identical
    /// JSON to the OLD "expand all oldest-first, then return the `count`-long tail after
    /// skipping `from`" logic, across a matrix of (count, from) including edges. The OLD logic
    /// is kept inline here as the reference oracle.
    #[test]
    fn listtransactions_windowing_matches_old_slice() {
        // A representative history (oldest-first): plain receives, a self-transfer (send +
        // receive), a 2-recipient sendmany (2 sends), a change-only tx (0 entries), an unmined
        // own send, and an expired send.
        let txs_oldest_first = vec![
            tx_with(0x01, Some(10), false, &[(false, true, 100, false, 0)]), // receive
            tx_with(0x02, Some(11), false, &[(false, true, 200, false, 0)]), // receive
            tx_with(0x03, Some(12), false, &[(true, true, 50, false, 0)]),   // self-transfer
            tx_with(
                0x04,
                Some(13),
                false,
                &[(true, false, 60, false, 0), (true, false, 70, false, 1)],
            ), // sendmany
            tx_with(0x05, Some(14), false, &[(true, true, 80, true, 0)]), // change only -> 0 entries
            tx_with(0x06, None, false, &[(true, false, 90, false, 0)]),   // unmined own send
            tx_with(0x07, None, true, &[(true, false, 95, false, 0)]),    // expired send
            tx_with(0x08, Some(15), false, &[(false, true, 110, false, 0)]), // receive
        ];
        let st = status(20);
        let labels = HashMap::new();

        // The shared expander, identical to what `listtransactions` feeds the windower.
        let expand = |tx: &TxRecord| {
            let confirmations = tx_confirmations(&st, tx);
            let time = tx_time(tx, None);
            tx_entries(tx, &labels, confirmations, time, None)
        };

        // OLD reference oracle: expand everything oldest-first, slice the `count`-long tail.
        let old = |count: usize, from: usize| -> Vec<Value> {
            let mut entries: Vec<Value> = Vec::new();
            for tx in &txs_oldest_first {
                entries.extend(expand(tx));
            }
            let total = entries.len();
            let end = total.saturating_sub(from);
            let start = end.saturating_sub(count);
            entries[start..end].to_vec()
        };

        // NEW windowing operates on the newest-first tx list.
        let newest_first: Vec<TxRecord> = txs_oldest_first.iter().rev().cloned().collect();

        let total_entries = old(usize::MAX, 0).len();
        assert!(
            total_entries > 5,
            "fixture should expand to several entries"
        );
        for &count in &[0usize, 1, 2, 3, 5, total_entries, total_entries + 5, 1000] {
            for &from in &[0usize, 1, 2, total_entries, total_entries + 5, 1000] {
                let want = old(count, from);
                let got = window_history_from_txs(&newest_first, from, count, expand);
                assert_eq!(got, want, "windowing diverged at count={count} from={from}");
            }
        }
    }

    #[test]
    fn z_listtransactions_entry_shape() {
        // A mined Orchard send carrying a text memo and a known fee.
        let mut t = tx_with(
            0x09,
            Some(50),
            false,
            &[(true, false, 150_000_000, false, 2)],
        );
        t.expiry_height = Some(60);
        t.outputs[0].pool = 3;
        t.outputs[0].memo = Some(b"hello world".to_vec());
        let st = status(52);
        let e = z_tx_entries(&t, tx_confirmations(&st, &t), tx_time(&t, None));
        assert_eq!(e.len(), 1);
        let s = &e[0];
        assert_eq!(s["pool"], json!("orchard"));
        assert_eq!(s["category"], json!("send"));
        assert_eq!(s["amountZat"], json!(-150_000_000));
        assert_eq!(s["amount"].to_string(), "-1.50000000");
        assert_eq!(s["outindex"], json!(2));
        assert_eq!(s["outgoing"], json!(true));
        assert_eq!(s["change"], json!(false));
        assert_eq!(s["status"], json!("mined"));
        assert_eq!(s["confirmations"], json!(3));
        assert_eq!(s["blockheight"], json!(50));
        assert_eq!(s["blockhash"], json!("ee".repeat(32)));
        assert_eq!(s["expiryheight"], json!(60));
        assert_eq!(s["feeZat"], json!(-1_000));
        assert_eq!(s["fee"].to_string(), "-0.00001000");
        assert_eq!(s["walletconflicts"], json!([]));
        assert_eq!(s["memo"], json!(hex::encode(b"hello world")));
        assert_eq!(s["memoStr"], json!("hello world"));

        // A transparent receive: pool "transparent", positive amounts, no fee/outgoing, and
        // an unmined receive reports status "waiting" with no block fields.
        let mut r = tx_with(0x0a, None, false, &[(false, true, 250, false, 0)]);
        r.fee_paid = None;
        r.outputs[0].pool = 0;
        let e = z_tx_entries(&r, tx_confirmations(&st, &r), tx_time(&r, None));
        assert_eq!(e[0]["pool"], json!("transparent"));
        assert_eq!(e[0]["category"], json!("receive"));
        assert_eq!(e[0]["amountZat"], json!(250));
        assert_eq!(e[0]["outgoing"], json!(false));
        assert_eq!(e[0]["status"], json!("waiting"));
        assert!(e[0].get("fee").is_none());
        assert!(e[0].get("blockhash").is_none());
        assert!(e[0].get("memo").is_none());

        // An expired unmined tx reports status "expired".
        let x = tx_with(0x0b, None, true, &[(true, false, 5, false, 0)]);
        let e = z_tx_entries(&x, tx_confirmations(&st, &x), tx_time(&x, None));
        assert_eq!(e[0]["status"], json!("expired"));

        // Change outputs are filtered out (no entries).
        let c = tx_with(0x0c, Some(50), false, &[(true, true, 5, true, 0)]);
        assert!(z_tx_entries(&c, 1, 0).is_empty());
    }
}
