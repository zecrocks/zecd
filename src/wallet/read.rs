//! Read-only wallet queries served from short-lived connections, so they never block on the
//! sync writer (SQLite WAL gives consistent snapshots).
#![allow(dead_code)] // some TxRecord fields are surfaced selectively by RPC methods

use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use rusqlite::{named_params, Connection, OptionalExtension};
use uuid::Uuid;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{InputSource, WalletRead};
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

/// Aggregate balances via `get_wallet_summary` (mirrors devtool's `balance.rs`).
pub fn balance(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<BalanceInfo> {
    let db = open_read(network, wallet_dir)?;
    let mut info = BalanceInfo::default();
    if let Some(summary) = db.get_wallet_summary(ConfirmationsPolicy::default())? {
        for bal in summary.account_balances().values() {
            info.orchard_spendable += bal.orchard_balance().spendable_value().into_u64();
            info.sapling_spendable += bal.sapling_balance().spendable_value().into_u64();
            info.pending += bal.orchard_balance().value_pending_spendability().into_u64()
                + bal.sapling_balance().value_pending_spendability().into_u64();
            info.immature += bal.orchard_balance().change_pending_confirmation().into_u64()
                + bal.sapling_balance().change_pending_confirmation().into_u64();
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
    pub pool: i64,
    pub output_index: u32,
    pub from_account: Option<Uuid>,
    pub to_account: Option<Uuid>,
    pub to_address: Option<String>,
    pub value: i64,
    pub is_change: bool,
}

/// One transaction row from `v_transactions`, plus its outputs.
#[derive(Debug, Clone)]
pub struct TxRecord {
    pub mined_height: Option<u32>,
    pub txid_hex: String,
    pub expiry_height: Option<u32>,
    pub account_balance_delta: i64,
    pub fee_paid: Option<u64>,
    pub sent_note_count: i64,
    pub received_note_count: i64,
    pub block_time: Option<i64>,
    pub expired_unmined: bool,
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

fn load_outputs(conn: &Connection, txid: &[u8]) -> anyhow::Result<Vec<TxOutputRecord>> {
    let mut stmt = conn.prepare(
        "SELECT output_pool, output_index, from_account_uuid, to_account_uuid,
                to_address, value, is_change
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
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// All transactions, oldest first (callers apply skip/count). Mirrors `list_tx.rs`.
pub fn list_transactions(wallet_dir: &Path) -> anyhow::Result<Vec<TxRecord>> {
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare(
        "SELECT mined_height, txid, expiry_height, account_balance_delta, fee_paid,
                sent_note_count, received_note_count, block_time, expired_unmined,
                COALESCE(
                    mined_height,
                    CASE WHEN expiry_height == 0 THEN NULL ELSE expiry_height END
                ) AS sort_height
         FROM v_transactions
         ORDER BY sort_height ASC NULLS LAST",
    )?;
    let mut records = Vec::new();
    let rows = stmt.query_map([], |row| {
        let txid: Vec<u8> = row.get("txid")?;
        Ok((
            txid.clone(),
            TxRecord {
                mined_height: row.get("mined_height")?,
                txid_hex: txid_display(&txid),
                expiry_height: row.get("expiry_height")?,
                account_balance_delta: row.get("account_balance_delta")?,
                fee_paid: row.get::<_, Option<i64>>("fee_paid")?.map(|v| v as u64),
                sent_note_count: row.get("sent_note_count")?,
                received_note_count: row.get("received_note_count")?,
                block_time: row.get("block_time")?,
                expired_unmined: row.get("expired_unmined")?,
                outputs: Vec::new(),
                raw: None,
            },
        ))
    })?;
    let mut pending: Vec<(Vec<u8>, TxRecord)> = Vec::new();
    for r in rows {
        pending.push(r?);
    }
    for (txid, mut rec) in pending {
        rec.outputs = load_outputs(&conn, &txid)?;
        records.push(rec);
    }
    Ok(records)
}

/// A single transaction by its display-hex txid.
pub fn get_transaction(wallet_dir: &Path, txid_hex: &str) -> anyhow::Result<Option<TxRecord>> {
    let Some(internal) = txid_internal(txid_hex) else {
        return Ok(None);
    };
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare(
        "SELECT mined_height, txid, expiry_height, account_balance_delta, fee_paid,
                sent_note_count, received_note_count, block_time, expired_unmined
         FROM v_transactions
         WHERE txid = :txid",
    )?;
    let mut rows = stmt.query(named_params! {":txid": internal})?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let txid: Vec<u8> = row.get("txid")?;
    let mut rec = TxRecord {
        mined_height: row.get("mined_height")?,
        txid_hex: txid_display(&txid),
        expiry_height: row.get("expiry_height")?,
        account_balance_delta: row.get("account_balance_delta")?,
        fee_paid: row.get::<_, Option<i64>>("fee_paid")?.map(|v| v as u64),
        sent_note_count: row.get("sent_note_count")?,
        received_note_count: row.get("received_note_count")?,
        block_time: row.get("block_time")?,
        expired_unmined: row.get("expired_unmined")?,
        outputs: Vec::new(),
        raw: None,
    };
    drop(rows);
    rec.outputs = load_outputs(&conn, &txid)?;
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

/// Wallet transactions that are still unmined and unexpired at `tip` - candidates for
/// rebroadcast. Returns `(display_txid, raw_bytes)`; `raw` is only present for txs the
/// wallet created or has enhanced. An expiry height of 0 means "never expires".
///
/// Only transactions that spend this wallet's notes qualify (nobody else can spend them, so
/// such a tx was necessarily authored here). The actor's mempool stream also stores *foreign*
/// incoming txs as unmined rows with raw bytes, and those are the sender's to retransmit,
/// not ours.
pub fn unmined_raw_txs(wallet_dir: &Path, tip: u32) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare(
        "SELECT txid, raw, expiry_height FROM transactions t
         WHERE mined_height IS NULL AND raw IS NOT NULL
         AND (EXISTS (SELECT 1 FROM orchard_received_note_spends s
                      WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM sapling_received_note_spends s
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
    let mut stmt = conn.prepare(
        "SELECT time FROM blocks WHERE height <= :height ORDER BY height DESC LIMIT 11",
    )?;
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
    {
        let conn = open_conn(wallet_dir)?;
        let mut stmt = conn
            .prepare("SELECT txid, mined_height, account_balance_delta FROM v_transactions")?;
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
    }

    let mut out = Vec::new();
    for account in db.get_account_ids()? {
        let notes = db.select_unspent_notes(account, &[ShieldedProtocol::Orchard], target_height, &[])?;
        for note in notes.orchard() {
            let txid = note.txid().to_string();
            let value = note.note_value().map_err(|e| anyhow!("note value: {e:?}"))?.into_u64();
            let (mined_height, trusted) = tx_meta.get(&txid).copied().unwrap_or((None, false));
            out.push(UnspentNote {
                vout: note.output_index() as u32,
                txid,
                value,
                mined_height,
                trusted,
            });
        }
    }
    Ok(out)
}

/// Every address the wallet has generated, encoded for the network (for
/// `listreceivedbyaddress` with `include_empty`).
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
    }
    out
}

/// Whether `addr` is one of the wallet's own generated addresses (for `getaddressinfo.ismine`).
pub fn is_mine(network: ZNetwork, wallet_dir: &Path, addr: &str) -> bool {
    let Ok(db) = open_read(network, wallet_dir) else {
        return false;
    };
    let Ok(ids) = db.get_account_ids() else {
        return false;
    };
    for account in ids {
        if let Ok(list) = db.list_addresses(account) {
            if list.iter().any(|info| info.address().encode(&network) == addr) {
                return true;
            }
        }
    }
    false
}
