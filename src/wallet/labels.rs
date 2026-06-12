//! Small side-tables stored in `labels.sqlite` alongside the librustzcash-managed
//! `data.sqlite`: address→label mappings (librustzcash has no address-label concept) and
//! first-seen times for unmined transactions (for `gettransaction.timereceived`). They live
//! in a separate database so we never touch the schema librustzcash owns and migrates.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

const LABELS_DB: &str = "labels.sqlite";

fn open(wallet_dir: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(wallet_dir.join(LABELS_DB))?;
    conn.execute_batch(
        "PRAGMA busy_timeout = 5000;
         CREATE TABLE IF NOT EXISTS address_labels(
             address TEXT PRIMARY KEY,
             label   TEXT NOT NULL DEFAULT ''
         );
         CREATE TABLE IF NOT EXISTS tx_first_seen(
             txid TEXT PRIMARY KEY,
             time INTEGER NOT NULL
         );",
    )?;
    Ok(conn)
}

pub fn set_label(wallet_dir: &Path, address: &str, label: &str) -> rusqlite::Result<()> {
    let conn = open(wallet_dir)?;
    conn.execute(
        "INSERT INTO address_labels(address, label) VALUES (?1, ?2)
         ON CONFLICT(address) DO UPDATE SET label = excluded.label",
        params![address, label],
    )?;
    Ok(())
}

pub fn get_label(wallet_dir: &Path, address: &str) -> rusqlite::Result<Option<String>> {
    let conn = open(wallet_dir)?;
    let mut stmt = conn.prepare("SELECT label FROM address_labels WHERE address = ?1")?;
    let mut rows = stmt.query(params![address])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

/// All address→label mappings, for joining into `listtransactions`.
pub fn all(wallet_dir: &Path) -> rusqlite::Result<HashMap<String, String>> {
    let conn = open(wallet_dir)?;
    let mut stmt = conn.prepare("SELECT address, label FROM address_labels")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    let mut map = HashMap::new();
    for r in rows {
        let (a, l) = r?;
        map.insert(a, l);
    }
    Ok(map)
}

/// Addresses carrying a given label (for `getaddressesbylabel`).
pub fn addresses_for_label(wallet_dir: &Path, label: &str) -> rusqlite::Result<Vec<String>> {
    let conn = open(wallet_dir)?;
    let mut stmt = conn.prepare("SELECT address FROM address_labels WHERE label = ?1")?;
    let rows = stmt.query_map(params![label], |row| row.get::<_, String>(0))?;
    rows.collect()
}

/// Record when the wallet first saw a transaction (display-hex txid), if not already
/// recorded. The actor calls this for mempool-stream arrivals; wallet-created sends carry a
/// `created` timestamp in the librustzcash schema instead.
pub fn record_first_seen(wallet_dir: &Path, txid: &str, unix_time: i64) -> rusqlite::Result<()> {
    let conn = open(wallet_dir)?;
    conn.execute(
        "INSERT OR IGNORE INTO tx_first_seen(txid, time) VALUES (?1, ?2)",
        params![txid, unix_time],
    )?;
    Ok(())
}

/// The recorded first-seen time of one transaction, if any.
pub fn first_seen(wallet_dir: &Path, txid: &str) -> rusqlite::Result<Option<i64>> {
    let conn = open(wallet_dir)?;
    conn.query_row(
        "SELECT time FROM tx_first_seen WHERE txid = ?1",
        params![txid],
        |row| row.get(0),
    )
    .optional()
}

/// All recorded first-seen times, for joining into `listtransactions`.
pub fn first_seen_all(wallet_dir: &Path) -> rusqlite::Result<HashMap<String, i64>> {
    let conn = open(wallet_dir)?;
    let mut stmt = conn.prepare("SELECT txid, time FROM tx_first_seen")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
    let mut map = HashMap::new();
    for r in rows {
        let (t, time) = r?;
        map.insert(t, time);
    }
    Ok(map)
}
