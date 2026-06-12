//! Read-only wallet queries served from short-lived connections, so they never block on the
//! sync writer (SQLite WAL gives consistent snapshots).

use std::collections::HashMap;
use std::path::Path;

use anyhow::anyhow;
use rusqlite::{named_params, Connection, OptionalExtension};
use uuid::Uuid;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::data_api::{InputSource, TransparentOutputFilter, WalletRead};
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
/// given confirmations policy (callers default to [`ConfirmationsPolicy::default`], the
/// ZIP-315 trusted-3/untrusted-10 policy; `getbalance` maps an explicit `minconf` onto a
/// symmetric override).
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
    #[allow(dead_code)] // part of the row shape; not yet surfaced by an RPC
    pub expiry_height: Option<u32>,
    pub account_balance_delta: i64,
    pub fee_paid: Option<u64>,
    #[allow(dead_code)] // part of the row shape; not yet surfaced by an RPC
    pub sent_note_count: i64,
    #[allow(dead_code)] // part of the row shape; not yet surfaced by an RPC
    pub received_note_count: i64,
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
/// row, but tparty hands out (and its callers query by) the bare t-address. Empty for zecd
/// wallets (whose addresses have no transparent receiver), making the rewrite a no-op there.
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
            v.fee_paid, v.sent_note_count, v.received_note_count, v.block_time,
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
            sent_note_count: row.get("sent_note_count")?,
            received_note_count: row.get("received_note_count")?,
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

/// All transactions, oldest first (callers apply skip/count). Mirrors `list_tx.rs`.
pub fn list_transactions(wallet_dir: &Path) -> anyhow::Result<Vec<TxRecord>> {
    let conn = open_conn(wallet_dir)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {TX_COLS},
            COALESCE(
                v.mined_height,
                CASE WHEN v.expiry_height == 0 THEN NULL ELSE v.expiry_height END
            ) AS sort_height
         {TX_FROM}
         ORDER BY sort_height ASC NULLS LAST",
    ))?;
    let mut records = Vec::new();
    let rows = stmt.query_map([], tx_from_row)?;
    let mut pending: Vec<(Vec<u8>, TxRecord)> = Vec::new();
    for r in rows {
        pending.push(r?);
    }
    let taddr_map = transparent_receiver_map(&conn)?;
    for (txid, mut rec) in pending {
        rec.outputs = load_outputs(&conn, &txid, &taddr_map)?;
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
/// else can spend them, so such a tx was necessarily authored here - for tparty that
/// includes its auto-shielding txs, which spend the wallet's transparent UTXOs). The actor's
/// mempool stream also stores *foreign* incoming txs as unmined rows with raw bytes, and
/// those are the sender's to retransmit, not ours.
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
    // Map (txid, action index) -> receiving address for the Orchard outputs the wallet
    // recorded one for (change/internal notes have none).
    let mut out_addr: HashMap<(String, u32), String> = HashMap::new();
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
        let mut stmt = conn.prepare(
            "SELECT txid, output_index, to_address FROM v_tx_outputs
             WHERE output_pool = 3 AND to_address IS NOT NULL",
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
    for account in db.get_account_ids()? {
        let notes = db.select_unspent_notes(account, &[ShieldedProtocol::Orchard], target_height, &[])?;
        for note in notes.orchard() {
            let txid = note.txid().to_string();
            let vout = note.output_index() as u32;
            let value = note.note_value().map_err(|e| anyhow!("note value: {e:?}"))?.into_u64();
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
        }
    }

    // Mempool-received notes are invisible to `select_unspent_notes`: a note stored by
    // trial-decrypting an *unmined* transaction carries no nullifier (upstream's
    // `DecryptedOutput<orchard::Note>::nullifier()` is `None`; nf/position are filled in
    // when the tx is later scanned in a block) and the selector requires `nf IS NOT NULL`.
    // bitcoind's `listunspent minconf=0` lists unconfirmed wallet outputs, so supplement
    // with a direct query for unmined, unexpired, unspent Orchard notes. A spend only
    // suppresses a note while its spending tx is mined or unexpired - mirroring
    // `spent_notes_clause` - so an expired spend releases the note again.
    {
        let conn = open_conn(wallet_dir)?;
        let seen: std::collections::HashSet<(String, u32)> =
            out.iter().map(|u| (u.txid.clone(), u.vout)).collect();
        let mut stmt = conn.prepare(
            "SELECT t.txid, rn.action_index, rn.value
             FROM orchard_received_notes rn
             JOIN transactions t ON t.id_tx = rn.transaction_id
             WHERE t.mined_height IS NULL
               AND (t.expiry_height IS NULL OR t.expiry_height = 0
                    OR t.expiry_height >= :target)
               AND rn.id NOT IN (
                   SELECT rns.orchard_received_note_id
                   FROM orchard_received_note_spends rns
                   JOIN transactions stx ON stx.id_tx = rns.transaction_id
                   WHERE stx.mined_height IS NOT NULL
                      OR stx.expiry_height IS NULL OR stx.expiry_height = 0
                      OR stx.expiry_height >= :target
               )",
        )?;
        let rows = stmt.query_map(
            named_params! { ":target": u32::from(chain_height) + 1 },
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )?;
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

/// The wallet's exposed transparent receivers as base58 t-addresses, sorted (tparty's
/// deposit-address universe).
pub fn transparent_addresses(network: ZNetwork, wallet_dir: &Path) -> Vec<String> {
    let Ok(db) = open_read(network, wallet_dir) else {
        return Vec::new();
    };
    let Ok(ids) = db.get_account_ids() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for account in ids {
        if let Ok(receivers) = db.get_transparent_receivers(account, false, false) {
            out.extend(receivers.keys().map(|t| t.encode(&network)));
        }
    }
    out.sort();
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
            if list.iter().any(|info| info.address().encode(&network) == addr) {
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

/// Transparent (not-yet-shielded) balances, for tparty's `getbalance`/`getunconfirmedbalance`:
/// `spendable` is confirmed to `min_conf` and ready to shield; `pending` is everything the
/// wallet has seen (including mempool deposits) that hasn't reached spendability yet.
pub fn transparent_balance(
    network: ZNetwork,
    wallet_dir: &Path,
    min_conf: u32,
) -> anyhow::Result<(u64, u64)> {
    let db = open_read(network, wallet_dir)?;
    let Some(chain_height) = db.chain_height()? else {
        return Ok((0, 0));
    };
    let policy = match std::num::NonZeroU32::new(min_conf) {
        None => ConfirmationsPolicy::MIN,
        Some(n) => ConfirmationsPolicy::new_symmetrical(n, false),
    };
    let (mut spendable, mut pending) = (0u64, 0u64);
    for account in db.get_account_ids()? {
        let balances = db.get_transparent_balances(account, (chain_height + 1).into(), policy)?;
        for (_addr, (_origin, balance)) in balances {
            spendable += balance.spendable_value().into_u64();
            pending += balance.value_pending_spendability().into_u64();
        }
    }
    Ok((spendable, pending))
}

/// An unspent transparent output, for tparty's `listunspent`.
#[derive(Debug, Clone)]
pub struct TransparentUtxo {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub script_pubkey: Vec<u8>,
    pub value: u64,
    pub mined_height: Option<u32>,
}

/// List the wallet's unspent (not-yet-shielded) transparent outputs, including unconfirmed
/// ones; the caller applies minconf/maxconf filtering from `mined_height`.
pub fn list_transparent_unspent(
    network: ZNetwork,
    wallet_dir: &Path,
) -> anyhow::Result<Vec<TransparentUtxo>> {
    let db = open_read(network, wallet_dir)?;
    let Some(chain_height) = db.chain_height()? else {
        return Ok(vec![]);
    };
    let target_height = (chain_height + 1).into();
    let mut out = Vec::new();
    for account in db.get_account_ids()? {
        let receivers = db.get_transparent_receivers(account, true, true)?;
        for taddr in receivers.keys() {
            let utxos = db.get_spendable_transparent_outputs(
                taddr,
                target_height,
                // Include 0-conf outputs; the RPC layer filters on confirmations.
                ConfirmationsPolicy::MIN,
                TransparentOutputFilter::All,
            )?;
            for utxo in utxos {
                let outpoint = utxo.outpoint();
                let mut txid_bytes = outpoint.hash().to_vec();
                txid_bytes.reverse();
                out.push(TransparentUtxo {
                    txid: hex::encode(txid_bytes),
                    vout: outpoint.n(),
                    address: taddr.encode(&network),
                    script_pubkey: utxo.txout().script_pubkey().0 .0.clone(),
                    value: utxo.txout().value().into_u64(),
                    mined_height: utxo.mined_height().map(u32::from),
                });
            }
        }
    }
    Ok(out)
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
        assert_eq!(parse(Some("2026-06-11 09:31:53.1234567+00:00")), Some(1_781_170_313));
        // A non-UTC offset is normalized to the same UTC epoch.
        assert_eq!(parse(Some("2026-06-11 09:31:53.1234567+02:00")), Some(1_781_163_113));
        assert_eq!(parse(None), None);
    }
}
