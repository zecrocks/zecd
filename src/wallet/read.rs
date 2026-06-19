//! Read-only wallet queries served from short-lived connections, so they never block on the
//! sync writer (SQLite WAL gives consistent snapshots).

use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use rusqlite::{named_params, Connection, OptionalExtension};
use uuid::Uuid;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{InputSource, WalletRead};
use zcash_keys::encoding::AddressCodec as _;
use zcash_protocol::ShieldedProtocol;

use crate::network::ZNetwork;
use crate::wallet::open::{data_db_path, open_read};

/// Spendable / pending balances aggregated across the wallet's accounts (in zatoshis).
#[derive(Debug, Default, Clone)]
pub struct BalanceInfo {
    pub orchard_spendable: u64,
    pub sapling_spendable: u64,
    pub total_spendable: u64,
    /// Value received but not yet spendable (needs more confirmations).
    pub pending: u64,
    /// Change awaiting confirmation.
    pub immature: u64,
}

/// Aggregate balances via `get_wallet_summary` (mirrors devtool's `balance.rs`), under the
/// given confirmations policy. Callers pass the wallet's configured policy
/// (`handle.confirmations`; ZIP-315 trusted-3/untrusted-10 by default) - never
/// `ConfirmationsPolicy::default()` directly - so balances agree with what a send can spend;
/// `getbalance` maps an explicit `minconf` onto a symmetric override.
pub fn balance(
    network: ZNetwork,
    wallet_dir: &Path,
    policy: ConfirmationsPolicy,
) -> anyhow::Result<BalanceInfo> {
    let db = open_read(network, wallet_dir)?;
    let mut info = BalanceInfo::default();
    if let Some(summary) = db.get_wallet_summary(policy)? {
        for bal in summary.account_balances().values() {
            info.orchard_spendable += bal.orchard_balance().spendable_value().into_u64();
            info.sapling_spendable += bal.sapling_balance().spendable_value().into_u64();
            info.pending += bal
                .orchard_balance()
                .value_pending_spendability()
                .into_u64()
                + bal
                    .sapling_balance()
                    .value_pending_spendability()
                    .into_u64();
            info.immature += bal
                .orchard_balance()
                .change_pending_confirmation()
                .into_u64()
                + bal
                    .sapling_balance()
                    .change_pending_confirmation()
                    .into_u64();
        }
        info.total_spendable = info.orchard_spendable + info.sapling_spendable;
    }
    Ok(info)
}

/// Number of transactions in the wallet (for `getwalletinfo.txcount`).
pub fn tx_count(wallet_dir: &Path) -> anyhow::Result<u64> {
    let conn = open_conn(wallet_dir)?;
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM v_transactions", [], |r| r.get(0))?;
    Ok(n as u64)
}

/// One output row from `v_tx_outputs`.
#[derive(Debug, Clone)]
pub struct TxOutputRecord {
    /// `v_tx_outputs.output_pool`: 0 = transparent, 2 = Sapling, 3 = Orchard.
    pub pool: i64,
    pub output_index: u32,
    pub from_account: Option<Uuid>,
    pub to_account: Option<Uuid>,
    pub to_address: Option<String>,
    pub value: i64,
    pub is_change: bool,
    /// The output's ZIP-302 memo bytes, when the wallet decrypted/stored one.
    pub memo: Option<Vec<u8>>,
}

/// One transaction row from `v_transactions`, plus its outputs.
#[derive(Debug, Clone)]
pub struct TxRecord {
    pub mined_height: Option<u32>,
    pub txid_hex: String,
    pub expiry_height: Option<u32>,
    pub account_balance_delta: i64,
    pub fee_paid: Option<u64>,
    pub block_time: Option<i64>,
    pub expired_unmined: bool,
    /// Position of the transaction within its block, when known (`blockindex`).
    pub tx_index: Option<u32>,
    /// Display-hex hash of the mining block, when scanned (`blockhash`).
    pub block_hash: Option<String>,
    /// Unix time the wallet created the transaction (librustzcash sets `created` only for
    /// wallet-authored sends); the unmined-tx `time`/`timereceived` fallback.
    pub created_time: Option<i64>,
    pub outputs: Vec<TxOutputRecord>,
    /// Raw serialized transaction bytes, when available (populated by `get_transaction`).
    pub raw: Option<Vec<u8>>,
}

/// An unspent Orchard note, for `listunspent`.
#[derive(Debug, Clone)]
pub struct UnspentNote {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub mined_height: Option<u32>,
    /// Whether this wallet authored the transaction that created the note (it spent from the
    /// account). Bitcoin Core's `listunspent.safe` analog: an *own* unconfirmed note (change)
    /// is trusted, a foreign unconfirmed note is not.
    pub trusted: bool,
    /// The diversified address the note was received on, when the wallet recorded one
    /// (change/internal notes have none).
    pub address: Option<String>,
}

fn open_conn(wallet_dir: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open(data_db_path(wallet_dir))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// Convert internal txid bytes to conventional (reversed) display hex.
fn txid_display(bytes: &[u8]) -> String {
    let mut b = bytes.to_vec();
    b.reverse();
    hex::encode(b)
}

/// Convert a display-hex txid back to internal byte order for lookups.
fn txid_internal(display_hex: &str) -> Option<Vec<u8>> {
    let mut b = hex::decode(display_hex).ok()?;
    if b.len() != 32 {
        return None;
    }
    b.reverse();
    Some(b)
}

/// Map from an address row's canonical encoding (`addresses.address`, a unified address) to
/// its transparent receiver, for the wallet's transparent-capable addresses. Used to report
/// received transparent outputs under the t-address the payer actually paid: the
/// `v_tx_outputs.to_address` column carries the *unified* encoding of the receiving address
/// row, but callers may query by the bare t-address. Empty for wallets whose addresses have
/// no transparent receiver (zecd's), making the rewrite a no-op there.
fn transparent_receiver_map(conn: &Connection) -> anyhow::Result<HashMap<String, String>> {
    let mut stmt = conn.prepare(
        "SELECT address, cached_transparent_receiver_address
         FROM addresses
         WHERE cached_transparent_receiver_address IS NOT NULL",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut map = HashMap::new();
    for r in rows {
        let (ua, taddr) = r?;
        map.insert(ua, taddr);
    }
    Ok(map)
}

fn load_outputs(
    conn: &Connection,
    txid: &[u8],
    taddr_map: &HashMap<String, String>,
) -> anyhow::Result<Vec<TxOutputRecord>> {
    let mut stmt = conn.prepare(
        "SELECT output_pool, output_index, from_account_uuid, to_account_uuid,
                to_address, value, is_change, memo
         FROM v_tx_outputs
         WHERE txid = :txid",
    )?;
    let rows = stmt.query_map(named_params! {":txid": txid}, |row| {
        Ok(TxOutputRecord {
            pool: row.get("output_pool")?,
            output_index: row.get("output_index")?,
            from_account: row.get::<_, Option<Uuid>>("from_account_uuid")?,
            to_account: row.get::<_, Option<Uuid>>("to_account_uuid")?,
            to_address: row.get("to_address")?,
            value: row.get("value")?,
            is_change: row.get("is_change")?,
            memo: row.get("memo")?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        let mut rec = r?;
        // A *received* transparent output (pool 0) was necessarily paid to the address row's
        // transparent receiver; report the t-address rather than the row's unified encoding.
        if rec.pool == 0 && rec.to_account.is_some() {
            if let Some(taddr) = rec.to_address.as_ref().and_then(|a| taddr_map.get(a)) {
                rec.to_address = Some(taddr.clone());
            }
        }
        out.push(rec);
    }
    Ok(out)
}

/// The column list shared by [`list_transactions`] and [`get_transaction`]: `v_transactions`
/// joined with the mining block's hash and the raw `transactions` row's `created` timestamp
/// (set only for wallet-authored sends; stored as `yyyy-MM-dd HH:mm:ss.fffffffzzz`, which
/// SQLite's date parser understands).
const TX_COLS: &str = "v.mined_height, v.txid, v.expiry_height, v.account_balance_delta,
            v.fee_paid, v.block_time,
            v.expired_unmined, v.tx_index,
            b.hash AS block_hash,
            CAST(strftime('%s', t.created) AS INTEGER) AS created_time";

/// The matching source clause for [`TX_COLS`].
const TX_FROM: &str = "FROM v_transactions v
     LEFT JOIN blocks b ON b.height = v.mined_height
     LEFT JOIN transactions t ON t.txid = v.txid";

/// Parse one [`TX_COLS`] row into `(internal txid, TxRecord)` (outputs filled by callers).
fn tx_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(Vec<u8>, TxRecord)> {
    let txid: Vec<u8> = row.get("txid")?;
    Ok((
        txid.clone(),
        TxRecord {
            mined_height: row.get("mined_height")?,
            txid_hex: txid_display(&txid),
            expiry_height: row.get("expiry_height")?,
            account_balance_delta: row.get("account_balance_delta")?,
            fee_paid: row.get::<_, Option<i64>>("fee_paid")?.map(|v| v as u64),
            block_time: row.get("block_time")?,
            expired_unmined: row.get("expired_unmined")?,
            tx_index: row.get("tx_index")?,
            block_hash: row
                .get::<_, Option<Vec<u8>>>("block_hash")?
                .map(|h| txid_display(&h)),
            created_time: row.get("created_time")?,
            outputs: Vec::new(),
            raw: None,
        },
    ))
}

/// Filter/pagination for [`query_transactions`], mirroring zcashd's height-range and
/// count/from arguments. The history/received-by RPCs push their windowing through this so
/// neither memory nor the per-tx [`load_outputs`] query scales with the whole wallet.
#[derive(Debug, Clone, Default)]
pub struct TxQuery {
    /// Lowest mined height to include (inclusive); `None` imposes no lower bound. Unmined txs
    /// are included only when `end_height` is also `None` (matching zcashd's predicate, which
    /// keeps unmined txs in an open-ended range but drops them once an upper bound is set).
    pub start_height: Option<u32>,
    /// Exclusive upper mined-height bound; `None` imposes no upper bound (and admits unmined).
    pub end_height: Option<u32>,
    /// Rows to skip after ordering (`LIMIT ... OFFSET`).
    pub offset: u32,
    /// Maximum rows to return; `None` means all (`LIMIT -1`).
    pub limit: Option<u32>,
    /// Order newest-first (`sort_height DESC NULLS FIRST`) instead of oldest-first.
    pub newest_first: bool,
}

/// Transactions matching `q`, each with its outputs. The WHERE clause mirrors zcashd's
/// height predicate (`rpcwallet.cpp` `listsinceblock`/`listreceivedbyaddress` range), and the
/// `sort_height` ordering (mined height, else a non-zero expiry height) matches what
/// [`list_transactions`] used before pagination moved into SQL. [`load_outputs`] stays per-tx
/// but is now bounded by `limit`, not the whole wallet.
pub fn query_transactions(wallet_dir: &Path, q: &TxQuery) -> anyhow::Result<Vec<TxRecord>> {
    let conn = open_conn(wallet_dir)?;
    let order = if q.newest_first {
        "ORDER BY sort_height DESC NULLS FIRST"
    } else {
        "ORDER BY sort_height ASC NULLS LAST"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT {TX_COLS},
            COALESCE(
                v.mined_height,
                CASE WHEN v.expiry_height == 0 THEN NULL ELSE v.expiry_height END
            ) AS sort_height
         {TX_FROM}
         WHERE (:start_height IS NULL OR v.mined_height >= :start_height
                OR (v.mined_height IS NULL AND :end_height IS NULL))
           AND (:end_height IS NULL OR v.mined_height < :end_height)
         {order}
         LIMIT :limit OFFSET :offset",
    ))?;
    let rows = stmt.query_map(
        named_params! {
            ":start_height": q.start_height,
            ":end_height": q.end_height,
            // LIMIT -1 means "no limit" in SQLite.
            ":limit": q.limit.map(i64::from).unwrap_or(-1),
            ":offset": q.offset,
        },
        tx_from_row,
    )?;
    let mut pending: Vec<(Vec<u8>, TxRecord)> = Vec::new();
    for r in rows {
        pending.push(r?);
    }
    let taddr_map = transparent_receiver_map(&conn)?;
    let mut records = Vec::with_capacity(pending.len());
    for (txid, mut rec) in pending {
        rec.outputs = load_outputs(&conn, &txid, &taddr_map)?;
        records.push(rec);
    }
    Ok(records)
}

/// All transactions, oldest first (callers apply skip/count). Mirrors `list_tx.rs`. A thin
/// wrapper over [`query_transactions`] with no filtering, kept for callers that genuinely
/// want the whole history (`gettransaction.details` aggregation, tests).
pub fn list_transactions(wallet_dir: &Path) -> anyhow::Result<Vec<TxRecord>> {
    query_transactions(wallet_dir, &TxQuery::default())
}

/// A lightweight data source for the received-by aggregations
/// (`getreceivedbyaddress`/`listreceivedbyaddress`/`getreceivedbylabel`/`listreceivedbylabel`),
/// avoiding [`list_transactions`]'s N+1 [`load_outputs`] and its per-tx memo/raw/block-hash
/// overhead. One flat query joins `v_transactions` to `v_tx_outputs`; the rows are grouped
/// into [`TxRecord`]s carrying only the fields the aggregation reads (`mined_height`,
/// `expired_unmined`, and each output's `to_account`/`to_address`/`value`/`is_change`), so the
/// existing - and tested - `received_by_address` logic produces identical output.
///
/// `address_filter` (display encoding) is pushed into SQL for `getreceivedbyaddress`, which
/// asks about a single address: only its outputs are loaded. The transparent-receiver rewrite
/// (a no-op for zecd, which exposes no transparent receivers) matches [`load_outputs`] so a
/// bare t-address filter aggregates the same as through the full path.
pub fn received_tx_records(
    wallet_dir: &Path,
    address_filter: Option<&str>,
) -> anyhow::Result<Vec<TxRecord>> {
    let conn = open_conn(wallet_dir)?;
    let taddr_map = transparent_receiver_map(&conn)?;
    // The filter may be a bare t-address; map it back to the unified encoding stored in
    // `v_tx_outputs.to_address` so the pushed-down predicate matches the stored rows.
    let ua_for_taddr: HashMap<&str, &str> = taddr_map
        .iter()
        .map(|(ua, t)| (t.as_str(), ua.as_str()))
        .collect();
    let stored_filter = address_filter.map(|a| ua_for_taddr.get(a).copied().unwrap_or(a));
    // Order by the same `sort_height` (oldest-first) as `list_transactions`, so the per-address
    // `txids` list `listreceivedbyaddress` emits is in the identical order it was before this
    // flat path replaced the full N+1 load.
    let mut stmt = conn.prepare(
        "SELECT v.txid, v.mined_height, v.expired_unmined,
                o.to_address, o.value, o.is_change, o.to_account_uuid, o.output_pool
         FROM v_transactions v
         JOIN v_tx_outputs o ON o.txid = v.txid
         WHERE (:addr IS NULL OR o.to_address = :addr)
         ORDER BY COALESCE(
                v.mined_height,
                CASE WHEN v.expiry_height == 0 THEN NULL ELSE v.expiry_height END
            ) ASC NULLS LAST",
    )?;
    let rows = stmt.query_map(named_params! { ":addr": stored_filter }, |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Option<u32>>(1)?,
            row.get::<_, bool>(2)?,
            TxOutputRecord {
                // `output_index`/`from_account`/`memo` are unused by the aggregation; `pool`
                // is read because it gates the transparent-receiver rewrite below (it must be
                // the real pool, exactly as `load_outputs` does - not a hardcoded 0).
                pool: row.get(7)?,
                output_index: 0,
                from_account: None,
                to_account: row.get::<_, Option<Uuid>>(6)?,
                to_address: row.get(3)?,
                value: row.get(4)?,
                is_change: row.get(5)?,
                memo: None,
            },
        ))
    })?;
    // Group outputs back under their transaction, preserving first-seen txid order.
    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut by_txid: HashMap<Vec<u8>, TxRecord> = HashMap::new();
    for r in rows {
        let (txid, mined_height, expired_unmined, mut out) = r?;
        if out.pool == 0 && out.to_account.is_some() {
            if let Some(t) = out.to_address.as_ref().and_then(|a| taddr_map.get(a)) {
                out.to_address = Some(t.clone());
            }
        }
        let rec = by_txid.entry(txid.clone()).or_insert_with(|| {
            order.push(txid.clone());
            TxRecord {
                mined_height,
                txid_hex: txid_display(&txid),
                expiry_height: None,
                account_balance_delta: 0,
                fee_paid: None,
                block_time: None,
                expired_unmined,
                tx_index: None,
                block_hash: None,
                created_time: None,
                outputs: Vec::new(),
                raw: None,
            }
        });
        rec.outputs.push(out);
    }
    Ok(order
        .into_iter()
        .map(|txid| by_txid.remove(&txid).expect("inserted above"))
        .collect())
}

/// A single transaction by its display-hex txid.
pub fn get_transaction(wallet_dir: &Path, txid_hex: &str) -> anyhow::Result<Option<TxRecord>> {
    let Some(internal) = txid_internal(txid_hex) else {
        return Ok(None);
    };
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare(&format!("SELECT {TX_COLS} {TX_FROM} WHERE v.txid = :txid"))?;
    let mut rows = stmt.query(named_params! {":txid": internal})?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let (txid, mut rec) = tx_from_row(row)?;
    drop(rows);
    rec.outputs = load_outputs(&conn, &txid, &transparent_receiver_map(&conn)?)?;
    // Fetch the raw transaction bytes for `gettransaction.hex`, if stored.
    rec.raw = conn
        .query_row(
            "SELECT raw FROM transactions WHERE txid = :txid",
            named_params! {":txid": &internal},
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten();
    Ok(Some(rec))
}

/// Whether the wallet database has a row for this transaction (display-hex txid). The actor
/// uses this to record first-seen times only for transactions that concern the wallet.
pub fn tx_exists(wallet_dir: &Path, txid_hex: &str) -> bool {
    let Some(internal) = txid_internal(txid_hex) else {
        return false;
    };
    let Ok(conn) = open_conn(wallet_dir) else {
        return false;
    };
    conn.query_row(
        "SELECT 1 FROM transactions WHERE txid = :txid",
        named_params! {":txid": internal},
        |_| Ok(()),
    )
    .optional()
    .ok()
    .flatten()
    .is_some()
}

/// Wallet transactions that are still unmined and unexpired at `tip` - candidates for
/// rebroadcast. Returns `(display_txid, raw_bytes)`; `raw` is only present for txs the
/// wallet created or has enhanced. An expiry height of 0 means "never expires".
///
/// Only transactions that spend this wallet's notes or transparent outputs qualify (nobody
/// else can spend them, so such a tx was necessarily authored here). The actor's mempool
/// stream also stores *foreign* incoming txs as unmined rows with raw bytes, and those are
/// the sender's to retransmit, not ours.
pub fn unmined_raw_txs(wallet_dir: &Path, tip: u32) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare(
        "SELECT txid, raw, expiry_height FROM transactions t
         WHERE mined_height IS NULL AND raw IS NOT NULL
         AND (EXISTS (SELECT 1 FROM orchard_received_note_spends s
                      WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM sapling_received_note_spends s
                         WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM transparent_received_output_spends s
                         WHERE s.transaction_id = t.id_tx))",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Option<u32>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (txid, raw, expiry) = r?;
        let unexpired = match expiry {
            None | Some(0) => true,
            Some(e) => e > tip,
        };
        if unexpired {
            out.push((txid_display(&txid), raw));
        }
    }
    Ok(out)
}

/// The `(display-hex hash, unix time)` of a block the wallet has scanned, from the wallet's
/// `blocks` table. Hashes are stored in internal byte order and displayed reversed, like txids.
pub fn block_info_at(wallet_dir: &Path, height: u32) -> anyhow::Result<Option<(String, i64)>> {
    let conn = open_conn(wallet_dir)?;
    let row = conn
        .query_row(
            "SELECT hash, time FROM blocks WHERE height = :height",
            named_params! {":height": height},
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?;
    Ok(row.map(|(hash, time)| (txid_display(&hash), time)))
}

/// The earliest block the wallet has scanned, as `(height, display-hex hash)` - the lowest
/// cursor `listsinceblock` can hand out when the requested depth predates the wallet.
pub fn first_scanned_block(wallet_dir: &Path) -> anyhow::Result<Option<(u32, String)>> {
    let conn = open_conn(wallet_dir)?;
    let row = conn
        .query_row(
            "SELECT height, hash FROM blocks ORDER BY height ASC LIMIT 1",
            [],
            |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    Ok(row.map(|(h, hash)| (h, txid_display(&hash))))
}

/// The height of a wallet-scanned block, looked up by its display-hex hash (for
/// `listsinceblock`). Hashes are stored in internal byte order, displayed reversed.
pub fn block_height_by_hash(wallet_dir: &Path, display_hash: &str) -> anyhow::Result<Option<u32>> {
    let Some(internal) = txid_internal(display_hash) else {
        return Ok(None);
    };
    let conn = open_conn(wallet_dir)?;
    let h = conn
        .query_row(
            "SELECT height FROM blocks WHERE hash = :hash",
            named_params! {":hash": internal},
            |r| r.get::<_, u32>(0),
        )
        .optional()?;
    Ok(h)
}

/// The median-time-past at `height`: the median of the (up to) 11 scanned block times ending
/// at `height` inclusive - the consensus MTP rule, for `getblockchaininfo.mediantime`.
pub fn median_time_past(wallet_dir: &Path, height: u32) -> anyhow::Result<Option<i64>> {
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn
        .prepare("SELECT time FROM blocks WHERE height <= :height ORDER BY height DESC LIMIT 11")?;
    let rows = stmt.query_map(named_params! {":height": height}, |r| r.get::<_, i64>(0))?;
    let mut times: Vec<i64> = rows.collect::<Result<_, _>>()?;
    if times.is_empty() {
        return Ok(None);
    }
    times.sort_unstable();
    Ok(Some(times[times.len() / 2]))
}

/// List unspent Orchard notes for `listunspent` (with mined height for confirmations).
pub fn list_unspent(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<Vec<UnspentNote>> {
    let db = open_read(network, wallet_dir)?;
    let Some(chain_height) = db.chain_height()? else {
        return Ok(vec![]);
    };
    let target_height = (chain_height + 1).into();

    // Map txid (display hex) -> (mined height, authored-by-us) for confirmations and trust.
    // A negative balance delta means the wallet spent notes in the tx, i.e. it authored it.
    let mut tx_meta: HashMap<String, (Option<u32>, bool)> = HashMap::new();
    // Map (txid, output index) -> receiving address for the shielded outputs the wallet recorded
    // one for (change/internal notes have none). Spans every shielded pool (2 = Sapling,
    // 3 = Orchard).
    let mut out_addr: HashMap<(String, u32), String> = HashMap::new();
    {
        let conn = open_conn(wallet_dir)?;
        let mut stmt =
            conn.prepare("SELECT txid, mined_height, account_balance_delta FROM v_transactions")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Option<u32>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (txid, mh, delta) = row?;
            tx_meta.insert(txid_display(&txid), (mh, delta < 0));
        }
        let mut stmt = conn.prepare(
            "SELECT txid, output_index, to_address FROM v_tx_outputs
             WHERE output_pool IN (2, 3) AND to_address IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (txid, idx, addr) = row?;
            out_addr.insert((txid_display(&txid), idx), addr);
        }
    }

    let mut out = Vec::new();
    // All shielded pools zecd supports; a note only exists if the wallet received it, so querying
    // every pool is safe regardless of which pools are enabled in config.
    let protocols: Vec<ShieldedProtocol> = crate::pools::Pool::SUPPORTED
        .iter()
        .map(|p| p.shielded_protocol())
        .collect();
    for account in db.get_account_ids()? {
        let notes = db.select_unspent_notes(account, &protocols, target_height, &[])?;
        // Both `notes.sapling()` and `notes.orchard()` yield `ReceivedNote`s with the same
        // `txid`/`output_index`/`note_value` surface; collect each into the shared output list.
        let mut push = |txid: String, vout: u32, value: u64| {
            let (mined_height, trusted) = tx_meta.get(&txid).copied().unwrap_or((None, false));
            let address = out_addr.get(&(txid.clone(), vout)).cloned();
            out.push(UnspentNote {
                vout,
                txid,
                value,
                mined_height,
                trusted,
                address,
            });
        };
        for note in notes.sapling() {
            let value = note
                .note_value()
                .map_err(|e| anyhow!("note value: {e:?}"))?
                .into_u64();
            push(note.txid().to_string(), note.output_index() as u32, value);
        }
        for note in notes.orchard() {
            let value = note
                .note_value()
                .map_err(|e| anyhow!("note value: {e:?}"))?
                .into_u64();
            push(note.txid().to_string(), note.output_index() as u32, value);
        }
    }

    // Mempool-received notes are invisible to `select_unspent_notes`: a note stored by
    // trial-decrypting an *unmined* transaction carries no nullifier (upstream's
    // `DecryptedOutput::nullifier()` is `None`; nf/position are filled in when the tx is later
    // scanned in a block) and the selector requires `nf IS NOT NULL`. bitcoind's
    // `listunspent minconf=0` lists unconfirmed wallet outputs, so supplement with a direct
    // query per shielded pool for unmined, unexpired, unspent notes. A spend only suppresses a
    // note while its spending tx is mined or unexpired - mirroring `spent_notes_clause` - so an
    // expired spend releases the note again.
    {
        let conn = open_conn(wallet_dir)?;
        let seen: std::collections::HashSet<(String, u32)> =
            out.iter().map(|u| (u.txid.clone(), u.vout)).collect();
        let target = u32::from(chain_height) + 1;
        // Per-pool table/column names differ only in three identifiers (note table, spend table,
        // FK column, and the output-index column), so run the same query shape for each pool.
        let pools: &[(&str, &str, &str, &str)] = &[
            (
                "sapling_received_notes",
                "sapling_received_note_spends",
                "sapling_received_note_id",
                "output_index",
            ),
            (
                "orchard_received_notes",
                "orchard_received_note_spends",
                "orchard_received_note_id",
                "action_index",
            ),
        ];
        for (note_table, spend_table, fk_col, index_col) in pools {
            let sql = format!(
                "SELECT t.txid, rn.{index_col}, rn.value
                 FROM {note_table} rn
                 JOIN transactions t ON t.id_tx = rn.transaction_id
                 WHERE t.mined_height IS NULL
                   AND (t.expiry_height IS NULL OR t.expiry_height = 0
                        OR t.expiry_height >= :target)
                   AND rn.id NOT IN (
                       SELECT rns.{fk_col}
                       FROM {spend_table} rns
                       JOIN transactions stx ON stx.id_tx = rns.transaction_id
                       WHERE stx.mined_height IS NOT NULL
                          OR stx.expiry_height IS NULL OR stx.expiry_height = 0
                          OR stx.expiry_height >= :target
                   )"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(named_params! { ":target": target }, |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (txid, vout, value) = row?;
                let txid = txid_display(&txid);
                if seen.contains(&(txid.clone(), vout)) {
                    continue;
                }
                let (mined_height, trusted) = tx_meta.get(&txid).copied().unwrap_or((None, false));
                let address = out_addr.get(&(txid.clone(), vout)).cloned();
                out.push(UnspentNote {
                    vout,
                    txid,
                    value: u64::try_from(value).unwrap_or(0),
                    mined_height,
                    trusted,
                    address,
                });
            }
        }
    }
    Ok(out)
}

/// Every address the wallet has generated, encoded for the network (for
/// `listreceivedbyaddress` with `include_empty`). Includes the wallet's exposed transparent
/// receivers as base58 t-addresses (a no-op for zecd wallets, which never expose any).
pub fn all_addresses(network: ZNetwork, wallet_dir: &Path) -> Vec<String> {
    let Ok(db) = open_read(network, wallet_dir) else {
        return Vec::new();
    };
    let Ok(ids) = db.get_account_ids() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for account in ids {
        if let Ok(list) = db.list_addresses(account) {
            out.extend(list.iter().map(|info| info.address().encode(&network)));
        }
        if let Ok(receivers) = db.get_transparent_receivers(account, false, false) {
            out.extend(receivers.keys().map(|t| t.encode(&network)));
        }
    }
    out
}

/// Whether `addr` is one of the wallet's own generated addresses (for `getaddressinfo.ismine`).
/// Matches both unified addresses and the wallet's transparent receivers.
pub fn is_mine(network: ZNetwork, wallet_dir: &Path, addr: &str) -> bool {
    let Ok(db) = open_read(network, wallet_dir) else {
        return false;
    };
    let Ok(ids) = db.get_account_ids() else {
        return false;
    };
    for account in ids {
        if let Ok(list) = db.list_addresses(account) {
            if list
                .iter()
                .any(|info| info.address().encode(&network) == addr)
            {
                return true;
            }
        }
        if let Ok(receivers) = db.get_transparent_receivers(account, false, false) {
            if receivers.keys().any(|t| t.encode(&network) == addr) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    /// The `created_time` expression in [`super::TX_COLS`] must parse rusqlite's
    /// `OffsetDateTime` encoding (`yyyy-MM-dd HH:mm:ss.fffffffzzz`, what librustzcash stores
    /// in `transactions.created`), honoring the offset, and yield NULL for NULL input.
    #[test]
    fn sqlite_parses_created_timestamp_format() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let parse = |s: Option<&str>| -> Option<i64> {
            conn.query_row(
                "SELECT CAST(strftime('%s', ?1) AS INTEGER)",
                rusqlite::params![s],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(
            parse(Some("2026-06-11 09:31:53.1234567+00:00")),
            Some(1_781_170_313)
        );
        // A non-UTC offset is normalized to the same UTC epoch.
        assert_eq!(
            parse(Some("2026-06-11 09:31:53.1234567+02:00")),
            Some(1_781_163_113)
        );
        assert_eq!(parse(None), None);
    }
}
