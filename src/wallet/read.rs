//! Read-only wallet queries served from short-lived connections, so they never block on the
//! sync writer (SQLite WAL gives consistent snapshots).

use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use rusqlite::{named_params, Connection, OptionalExtension};
use uuid::Uuid;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{Account as _, InputSource, WalletRead};
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_keys::encoding::AddressCodec as _;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::builder::DEFAULT_TX_EXPIRY_DELTA;
use zcash_protocol::{ShieldedProtocol, TxId};
use zip32::{DiversifierIndex, Scope};

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

/// `v_tx_outputs.recipient_key_scope` for an output received on one of the wallet's own
/// *external* (user-facing) addresses - the ZIP-32 external scope. Internal/change is `1`,
/// imported is `-1`, and a pure send (no wallet receive) or an unlinked address is `NULL`.
pub const EXTERNAL_KEY_SCOPE: i64 = 0;

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
    /// `v_tx_outputs.recipient_key_scope`: the ZIP-32 scope of the address this output was
    /// received on - [`EXTERNAL_KEY_SCOPE`] (`0`) external, `1` internal/change, `-1` imported,
    /// `None` when the output isn't a wallet receive (a pure send) or its address isn't linked.
    /// This - not [`Self::is_change`] - is the reliable "is this internal change" signal:
    /// librustzcash marks an output `is_change` whenever the *receiving* account also spent in
    /// the same transaction (scanning's `find_received`), so a deliberate payment to one of the
    /// wallet's own user-facing addresses lands with `is_change = true` despite being received
    /// on an external-scope address. See [`Self::is_internal_change`].
    pub recipient_key_scope: Option<i64>,
    /// The output's ZIP-302 memo bytes, when the wallet decrypted/stored one.
    pub memo: Option<Vec<u8>>,
}

impl TxOutputRecord {
    /// Whether this output is internal change that the history/detail RPCs hide. True change is
    /// `is_change` on an output received on a non-external scope (internal/imported/unlinked); a
    /// payment to one of the wallet's *own* user-facing (external) addresses is a deliberate
    /// self-send and stays visible - Bitcoin Core surfaces such a self-payment as a send+receive
    /// pair (and so its memo stays reachable). Filtering on raw `is_change` would wrongly hide
    /// it, because librustzcash flags self-payments `is_change` too.
    pub fn is_internal_change(&self) -> bool {
        self.is_change && self.recipient_key_scope != Some(EXTERNAL_KEY_SCOPE)
    }
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

/// SQL predicate that the transaction aliased `alias` is *unexpired*, a faithful port of
/// librustzcash's `zcash_client_sqlite::wallet::common::tx_unexpired_condition` - the canonical
/// rule that `select_unspent_notes`/`spent_notes_clause` and the balance queries use. We
/// reproduce it because there is no public API for the unmined/mempool notes and rebroadcast set
/// the raw queries below supplement; centralizing it (rather than open-coding a simpler expiry
/// test, as earlier copies did) keeps `listunspent minconf=0` and `unmined_raw_txs` in lockstep
/// with `getbalance` - including the `min_observed_height + DEFAULT_TX_EXPIRY_DELTA` staleness
/// branch (a tx with unknown expiry is treated as unexpired only while recently observed). The
/// caller must bind `:target_height` to the next-to-be-mined height (chain tip + 1). Keep this in
/// sync with upstream on every `zcash_client_sqlite` bump.
fn tx_unexpired_sql(alias: &str) -> String {
    format!(
        "{alias}.mined_height < :target_height
         OR {alias}.expiry_height = 0
         OR {alias}.expiry_height >= :target_height
         OR ({alias}.expiry_height IS NULL
             AND {alias}.min_observed_height + {DEFAULT_TX_EXPIRY_DELTA} >= :target_height)"
    )
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
                to_address, value, is_change, recipient_key_scope, memo
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
            recipient_key_scope: row.get::<_, Option<i64>>("recipient_key_scope")?,
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
/// (`getreceivedbyaddress`/`listreceivedbyaddress`),
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
                o.to_address, o.value, o.is_change, o.to_account_uuid, o.output_pool,
                o.recipient_key_scope
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
                recipient_key_scope: row.get::<_, Option<i64>>(8)?,
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
pub fn get_transaction(
    network: ZNetwork,
    wallet_dir: &Path,
    txid_hex: &str,
) -> anyhow::Result<Option<TxRecord>> {
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
    // Fetch the raw transaction bytes for `gettransaction.hex` via the public `WalletRead` API
    // (mirroring the actor's `do_get_raw_tx`) instead of reading librustzcash's internal
    // `transactions.raw` column directly: this yields the canonical consensus serialization off
    // the documented interface. `None` when the tx is unknown or its raw data isn't stored -
    // exactly the contract of the column read it replaces.
    rec.raw = <[u8; 32]>::try_from(internal)
        .ok()
        .and_then(|bytes| raw_tx_bytes(network, wallet_dir, TxId::from_bytes(bytes)));
    Ok(Some(rec))
}

/// Serialized bytes of a wallet-known transaction, via the public `WalletRead::get_transaction`.
/// `None` if the txid is unknown to the wallet or its raw data hasn't been stored yet.
fn raw_tx_bytes(network: ZNetwork, wallet_dir: &Path, txid: TxId) -> Option<Vec<u8>> {
    let db = open_read(network, wallet_dir).ok()?;
    let tx = db.get_transaction(txid).ok()??;
    let mut buf = Vec::new();
    tx.write(&mut buf).ok()?;
    Some(buf)
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
    // Unexpired is the shared `tx_unexpired_sql` predicate (same rule the selector uses), so the
    // rebroadcast set never diverges from what the wallet considers live. `:target_height` is the
    // next-to-be-mined height; `expiry_height >= tip + 1` is exactly the old `expiry > tip`.
    let unexpired = tx_unexpired_sql("t");
    let sql = format!(
        "SELECT txid, raw FROM transactions t
         WHERE mined_height IS NULL AND raw IS NOT NULL
         AND ({unexpired})
         AND (EXISTS (SELECT 1 FROM orchard_received_note_spends s
                      WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM sapling_received_note_spends s
                         WHERE s.transaction_id = t.id_tx)
              OR EXISTS (SELECT 1 FROM transparent_received_output_spends s
                         WHERE s.transaction_id = t.id_tx))"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(named_params! { ":target_height": tip + 1 }, |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (txid, raw) = r?;
        out.push((txid_display(&txid), raw));
    }
    Ok(out)
}

/// Display-hex txids of every wallet transaction that is still unmined (`mined_height` NULL),
/// including foreign incoming txs the mempool stream stored. Used to prune the actor's transient
/// in-memory first-seen map (which only ever matters for unmined txs).
pub fn unmined_txids(wallet_dir: &Path) -> anyhow::Result<Vec<String>> {
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare("SELECT txid FROM transactions WHERE mined_height IS NULL")?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(txid_display(&r?));
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
        // Both the note's own creating tx and any spending tx are gated by the shared
        // `tx_unexpired_sql` predicate, so this supplement and the rebroadcast set agree with the
        // selector/balances on exactly what "unexpired" means (incl. the unknown-expiry staleness
        // branch). A note is shown only if its creating tx is unmined and unexpired, and isn't
        // suppressed by a spend whose tx is still live (mined or unexpired) - an expired spend
        // releases the note again.
        let unexpired_t = tx_unexpired_sql("t");
        let unexpired_stx = tx_unexpired_sql("stx");
        for (note_table, spend_table, fk_col, index_col) in pools {
            let sql = format!(
                "SELECT t.txid, rn.{index_col}, rn.value
                 FROM {note_table} rn
                 JOIN transactions t ON t.id_tx = rn.transaction_id
                 WHERE t.mined_height IS NULL
                   AND ({unexpired_t})
                   AND rn.id NOT IN (
                       SELECT rns.{fk_col}
                       FROM {spend_table} rns
                       JOIN transactions stx ON stx.id_tx = rns.transaction_id
                       WHERE {unexpired_stx}
                   )"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(named_params! { ":target_height": target }, |r| {
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

/// Whether `addr` is an address one of this wallet's accounts can produce - for
/// `getaddressinfo.ismine`.
///
/// Two layers, cheapest first:
///
/// 1. **Recorded-address match.** An exact hit against `list_addresses`: addresses the wallet
///    handed out and persisted, plus any recovered from a received note during a scan. No crypto,
///    no decode.
/// 2. **Cryptographic attribution.** Failing that, decode the address and ask the account's
///    Unified Incoming Viewing Key whether it derived any *shielded* receiver, via
///    [`UnifiedIncomingViewingKey::decrypt_diversifiers`]. For each receiver that recovers a
///    diversifier index it is one FF1 decrypt of the diversifier plus one address
///    re-derivation/`pk_d` comparison - O(1) per receiver, never an index search. This is what
///    recognizes an address the wallet *generated but never recorded*: e.g. one issued before a
///    stateless (or any) from-seed restore that was never funded, so the scan never re-added it
///    to the `addresses` table.
///
/// Both shielded pools zecd supports - Sapling and Orchard - are covered. A multi-receiver
/// Unified Address is attributed as ours **only when *every* shielded receiver is ours at one
/// diversifier index** (the [`UaReceivers::MineConsistent`] verdict), not when merely one
/// receiver matches: see the threat-model note in the body - a UA that pairs the wallet's
/// receiver with a stranger's would otherwise read `ismine: true` while a sender pays the
/// stranger. A single-receiver UA (and a bare Sapling address) is tested directly. Transparent
/// receivers are never attributed to a viewing key (zecd never receives into the transparent pool,
/// and a transparent receiver can't be attributed without a gap-limit derivation scan), so a
/// **transparent receiver inside a UA is disqualifying**: because zecd never issues a transparent
/// receiver, a UA that carries one can never be an address this wallet handed out - it is the same
/// splice as a foreign shielded receiver (a transparent-only sender would pay the attacker), and is
/// rejected even when a shielded receiver alongside it genuinely is the wallet's. A bare transparent
/// address is likewise never ours.
pub fn is_mine(network: ZNetwork, wallet_dir: &Path, addr: &str) -> bool {
    let Ok(db) = open_read(network, wallet_dir) else {
        return false;
    };
    let Ok(ids) = db.get_account_ids() else {
        return false;
    };
    // Decode once for the crypto path; `None` (unparseable / wrong network) just skips it.
    let decoded = crate::address::decode_on_network(&network, addr);
    for account in ids {
        // (1) Recorded-address fast path.
        if let Ok(list) = db.list_addresses(account) {
            if list
                .iter()
                .any(|info| info.address().encode(&network) == addr)
            {
                return true;
            }
        }
        // (2) Cryptographic attribution against the account's viewing key.
        let Some(decoded) = decoded.as_ref() else {
            continue;
        };
        let Ok(Some(acct)) = db.get_account(account) else {
            continue;
        };
        let Some(ufvk) = acct.ufvk() else {
            continue;
        };
        let uivk = ufvk.to_unified_incoming_viewing_key();
        let mine = match decoded {
            // THREAT MODEL - the "unexpected receiver" UA splice. A naive "any one receiver is
            // mine ⇒ the address is mine" rule lets an attacker hand the wallet a UA that pairs
            // *their* Orchard receiver with the victim's Sapling receiver: attribution says
            // "yours", but a ZIP-316 sender prefers Orchard and pays the attacker (and a
            // Sapling-only sender pays the attacker too if the foreign receiver sits in the only
            // pool it supports). Any foreign receiver is therefore disqualifying. So a UA with two
            // shielded receivers is ours ONLY when every receiver is ours at a single diversifier
            // index (`MineConsistent`) - never when it mixes in a stranger's receiver or staples
            // our own receivers from different indices. A UA with a single shielded receiver has
            // nothing to splice, so the plain viewing-key membership test stands (this is what
            // still recognizes a wallet-generated-but-unrecorded address after a restore).
            Address::Unified(ua) if ua.transparent().is_some() => {
                // A transparent receiver is itself a splice zecd can never have issued: zecd
                // receives only into shielded pools, so it never puts a transparent receiver in a
                // UA it hands out. An attacker can therefore staple *their* transparent receiver
                // onto the victim's Orchard/Sapling receiver - the shielded receiver is genuinely
                // the wallet's, but a transparent-only (or transparent-preferring) sender pays the
                // attacker. Since the count-shielded-receivers test below sees only one shielded
                // receiver, that UA would slip through the single-receiver membership check; so a
                // transparent receiver is unconditionally disqualifying here, exactly as a foreign
                // shielded receiver is in the two-shielded case.
                false
            }
            Address::Unified(ua) => {
                let two_shielded =
                    u8::from(ua.sapling().is_some()) + u8::from(ua.orchard().is_some()) >= 2;
                if two_shielded {
                    classify_receivers_with_ufvk(ufvk, ua) == UaReceivers::MineConsistent
                } else {
                    // decrypt_diversifiers runs Sapling decrypt_diversifier + Orchard
                    // diversifier_index; non-empty ⇒ the sole shielded receiver is ours.
                    !uivk.decrypt_diversifiers(ua).is_empty()
                }
            }
            // A bare Sapling address: the same membership test on the Sapling receiver alone.
            Address::Sapling(pa) => uivk
                .sapling()
                .as_ref()
                .and_then(|ivk| ivk.decrypt_diversifier(pa))
                .is_some(),
            // Transparent / TEX: intentionally unsupported (see the doc comment).
            Address::Transparent(_) | Address::Tex(_) => false,
        };
        if mine {
            return true;
        }
    }
    false
}

/// How a unified address's shielded receivers relate to *this wallet's* account key - the basis
/// for rejecting hand-spliced UAs (receivers stapled together from different diversifier indices,
/// or a mix of this wallet's receiver and a stranger's). A diversifier *index* is key-relative
/// (`FF1⁻¹(dk, d)` under the viewing key), so this is only computable against the wallet's own
/// keys; a UA whose receivers are all someone else's is simply [`UaReceivers::Foreign`].
#[derive(Debug, PartialEq, Eq)]
pub enum UaReceivers {
    /// Not a unified address, or a UA with at most one shielded receiver: nothing to cross-check
    /// (a single receiver cannot disagree with itself).
    NotApplicable,
    /// No shielded receiver derives from this wallet's account key(s).
    Foreign,
    /// Every shielded receiver derives from this wallet at the *same* (index, scope) - a
    /// well-formed address this wallet could itself have issued.
    MineConsistent,
    /// The receivers disagree: at least one belongs to this wallet and at least one does not, or
    /// they derive at *different* diversifier indices/scopes. A UA this wallet issued can never
    /// look like this, so it indicates receivers spliced together by hand.
    Inconsistent(String),
}

impl UaReceivers {
    /// An informational tri-state for inspection RPCs (`validateaddress`/`getaddressinfo`):
    /// `Some(true)` when every receiver is ours at one index, `Some(false)` when the receivers
    /// are spliced, and `None` when consistency is not computable/meaningful (a foreign UA - the
    /// index is the owner's secret - or a single-receiver address with nothing to cross-check).
    pub fn consistent_flag(&self) -> Option<bool> {
        match self {
            UaReceivers::MineConsistent => Some(true),
            UaReceivers::Inconsistent(_) => Some(false),
            UaReceivers::Foreign | UaReceivers::NotApplicable => None,
        }
    }
}

/// Recover an Orchard receiver's diversifier index (and scope) under a full viewing key, trying
/// both scopes. `None` if the receiver does not belong to the key.
fn orchard_receiver_index(
    fvk: &orchard::keys::FullViewingKey,
    addr: &orchard::Address,
) -> Option<(DiversifierIndex, Scope)> {
    [Scope::External, Scope::Internal]
        .into_iter()
        .find_map(|scope| {
            fvk.to_ivk(scope)
                .diversifier_index(addr)
                .map(|j| (j, scope))
        })
}

/// Classify a unified address's receivers against a single account's UFVK. Pure (no I/O) so it
/// can be unit-tested directly without a wallet DB.
fn classify_receivers_with_ufvk(ufvk: &UnifiedFullViewingKey, ua: &UnifiedAddress) -> UaReceivers {
    // For each present shielded receiver, recover its (index, scope) under this key. The outer
    // `Option` is presence; the inner is whether it belongs to this key.
    let recovered: [Option<Option<(DiversifierIndex, Scope)>>; 2] = [
        ua.sapling()
            .map(|a| ufvk.sapling().and_then(|dfvk| dfvk.decrypt_diversifier(a))),
        ua.orchard().map(|a| {
            ufvk.orchard()
                .and_then(|fvk| orchard_receiver_index(fvk, a))
        }),
    ];

    let mut resolved: Vec<(DiversifierIndex, Scope)> = Vec::new();
    let mut has_foreign_receiver = false;
    for slot in recovered.into_iter().flatten() {
        match slot {
            Some(found) => resolved.push(found),
            None => has_foreign_receiver = true,
        }
    }

    if resolved.is_empty() {
        return UaReceivers::Foreign; // none of the present receivers are ours
    }
    if has_foreign_receiver {
        return UaReceivers::Inconsistent(
            "unified address combines a receiver owned by this wallet with one that is not".into(),
        );
    }
    // Every present receiver resolved under this key; require a single (index, scope).
    let (first_idx, first_scope) = resolved[0];
    if resolved
        .iter()
        .all(|(j, s)| j.as_bytes() == first_idx.as_bytes() && *s == first_scope)
    {
        UaReceivers::MineConsistent
    } else {
        UaReceivers::Inconsistent(
            "unified address combines this wallet's receivers from different diversifier indices"
                .into(),
        )
    }
}

/// Classify a unified address's receivers against the wallet's own account key(s) - see
/// [`UaReceivers`]. Non-unified addresses and UAs carrying fewer than two shielded receivers are
/// [`UaReceivers::NotApplicable`]. Best-effort: storage errors degrade to `NotApplicable` rather
/// than erroring, so callers fall back to their existing (byte-exact) ownership checks.
pub fn classify_unified_receivers(network: ZNetwork, wallet_dir: &Path, addr: &str) -> UaReceivers {
    let Some(Address::Unified(ua)) = Address::decode(&network, addr) else {
        return UaReceivers::NotApplicable;
    };
    // Only meaningful when there are two shielded receivers to cross-check; zecd's shielded pools
    // are Sapling and Orchard, so that is exactly {sapling, orchard}.
    if u8::from(ua.sapling().is_some()) + u8::from(ua.orchard().is_some()) < 2 {
        return UaReceivers::NotApplicable;
    }
    let Ok(db) = open_read(network, wallet_dir) else {
        return UaReceivers::NotApplicable;
    };
    let Ok(ids) = db.get_account_ids() else {
        return UaReceivers::NotApplicable;
    };
    // One account per wallet today, but iterate so a future multi-account wallet still resolves
    // the receivers against whichever account owns them. The first non-`Foreign` verdict wins.
    for id in ids {
        let Ok(Some(account)) = db.get_account(id) else {
            continue;
        };
        let Some(ufvk) = account.ufvk() else {
            continue;
        };
        match classify_receivers_with_ufvk(ufvk, &ua) {
            UaReceivers::Foreign => {}
            other => return other,
        }
    }
    UaReceivers::Foreign
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The receiver-consistency classifier must accept a UA the wallet could itself issue (all
    /// receivers at one index), flag a UA spliced from receivers at *different* indices, and treat
    /// a UA built from a different key as foreign - so a hand-crafted address can't masquerade as
    /// the wallet's own across `getreceivedbyaddress`/`getaddressinfo`/`z_sendmany`.
    #[test]
    fn classify_receivers_detects_spliced_unified_address() {
        use zcash_keys::address::UnifiedAddress;
        use zcash_keys::keys::{ReceiverRequirement::*, UnifiedAddressRequest, UnifiedSpendingKey};
        use zcash_protocol::consensus::Network;
        use zip32::{AccountId, DiversifierIndex};

        let net = Network::MainNetwork;
        let account = AccountId::ZERO;
        // Two shielded receivers (Sapling + Orchard), no transparent.
        let request = UnifiedAddressRequest::unsafe_custom(Require, Require, Omit);

        let ufvk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], account)
            .unwrap()
            .to_unified_full_viewing_key();

        // Two of *our own* addresses at clearly different diversifier indices.
        let (ua_low, _) = ufvk.find_address(DiversifierIndex::new(), request).unwrap();
        let mut j = DiversifierIndex::new();
        for _ in 0..5000 {
            j.increment().unwrap();
        }
        let (ua_high, _) = ufvk.find_address(j, request).unwrap();
        assert_ne!(
            ua_low.encode(&net),
            ua_high.encode(&net),
            "the two indices must yield distinct addresses"
        );

        // A legitimately-issued address: every receiver at one index.
        assert_eq!(
            classify_receivers_with_ufvk(&ufvk, &ua_low),
            UaReceivers::MineConsistent
        );

        // Splice: our Sapling receiver from one index with our Orchard receiver from another.
        let spliced = UnifiedAddress::from_receivers(
            ua_high.orchard().cloned(),
            ua_low.sapling().cloned(),
            None,
        )
        .unwrap();
        assert!(
            matches!(
                classify_receivers_with_ufvk(&ufvk, &spliced),
                UaReceivers::Inconsistent(_)
            ),
            "receivers from different indices must be Inconsistent"
        );

        // Mix our Orchard receiver with a *stranger's* Sapling receiver.
        let other = UnifiedSpendingKey::from_seed(&net, &[9u8; 32], account)
            .unwrap()
            .to_unified_full_viewing_key();
        let (other_ua, _) = other
            .find_address(DiversifierIndex::new(), request)
            .unwrap();
        let mixed = UnifiedAddress::from_receivers(
            ua_low.orchard().cloned(),
            other_ua.sapling().cloned(),
            None,
        )
        .unwrap();
        assert!(
            matches!(
                classify_receivers_with_ufvk(&ufvk, &mixed),
                UaReceivers::Inconsistent(_)
            ),
            "one of our receivers mixed with a stranger's must be Inconsistent"
        );

        // A UA entirely from a different key is foreign, not an error.
        assert_eq!(
            classify_receivers_with_ufvk(&ufvk, &other_ua),
            UaReceivers::Foreign
        );
    }

    /// [`super::tx_unexpired_sql`] must reproduce librustzcash's `tx_unexpired_condition` across
    /// every branch: a mined tx (never "expired"), the never-expires (`expiry_height = 0`) case,
    /// expiry at/after vs strictly before the target, and the unknown-expiry staleness window
    /// (`min_observed_height + DEFAULT_TX_EXPIRY_DELTA`). This is the canonical spentness/expiry
    /// rule that our `listunspent minconf=0` supplement and `unmined_raw_txs` share with the
    /// selector and balances; this test pins the exact semantics (including the staleness branch
    /// our earlier hand-rolled copies dropped) so a `zcash_client_sqlite` bump that changes the
    /// rule is caught here. Thresholds are derived from `DEFAULT_TX_EXPIRY_DELTA` so the test
    /// tracks upstream if the constant moves.
    #[test]
    fn tx_unexpired_sql_matches_upstream_branches() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE tx(mined_height INTEGER, expiry_height INTEGER,
                             min_observed_height INTEGER NOT NULL);",
        )
        .unwrap();
        let pred = super::tx_unexpired_sql("tx");
        let target: i64 = 100;
        let delta = i64::from(super::DEFAULT_TX_EXPIRY_DELTA);
        // (mined_height, expiry_height, min_observed_height) -> expected "unexpired".
        let cases: &[(Option<i64>, Option<i64>, i64, bool)] = &[
            (Some(50), Some(80), 50, true), // mined (mined < target): never treated as expired
            (None, Some(0), 50, true),      // expiry 0 => never expires
            (None, Some(target), 50, true), // expiry == target => unexpired
            (None, Some(target + 5), 50, true), // expiry > target => unexpired
            (None, Some(target - 1), 50, false), // expiry < target => expired
            (None, None, target - delta, true), // unknown expiry, boundary: mo + delta == target
            (None, None, target - delta + 1, true), // unknown expiry, recently observed
            (None, None, target - delta - 1, false), // unknown expiry, stale => expired
        ];
        for (i, (m, e, mo, expected)) in cases.iter().enumerate() {
            conn.execute("DELETE FROM tx", []).unwrap();
            conn.execute(
                "INSERT INTO tx(mined_height, expiry_height, min_observed_height)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![m, e, mo],
            )
            .unwrap();
            let got: bool = conn
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM tx WHERE {pred})"),
                    rusqlite::named_params! { ":target_height": target },
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(got, *expected, "case {i}: ({m:?}, {e:?}, {mo})");
        }
    }
}
