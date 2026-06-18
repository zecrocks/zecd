//! Opening and initializing the per-wallet `zcash_client_sqlite` databases.
//! Ported from `zcash-devtool/src/data.rs`.

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;

use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::chain::BlockMeta;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};

use crate::network::ZNetwork;

const DATA_DB: &str = "data.sqlite";
const BLOCKS_FOLDER: &str = "blocks";

/// A read/write wallet handle (uses a real clock + OS RNG, required for writes).
pub type WriteDb = WalletDb<rusqlite::Connection, ZNetwork, SystemClock, OsRng>;
/// A read-only wallet handle (no clock/RNG needed), as used by devtool's read paths.
pub type ReadDb = WalletDb<rusqlite::Connection, ZNetwork, (), ()>;

pub fn data_db_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(DATA_DB)
}

pub fn block_path(wallet_dir: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&wallet_dir.join(BLOCKS_FOLDER))
}

/// Open the wallet DB for writing (sync, sends, address generation).
pub fn open_write(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<WriteDb> {
    Ok(WalletDb::for_path(
        data_db_path(wallet_dir),
        network,
        SystemClock,
        OsRng,
    )?)
}

/// Open the wallet DB read-only (balances, history); short-lived per request.
pub fn open_read(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<ReadDb> {
    Ok(WalletDb::for_path(
        data_db_path(wallet_dir),
        network,
        (),
        (),
    )?)
}

/// Open the compact-block cache.
pub fn open_fsblockdb(wallet_dir: &Path) -> anyhow::Result<FsBlockDb> {
    FsBlockDb::for_path(wallet_dir).map_err(|e| anyhow::anyhow!("opening block-cache db: {e}"))
}

/// Initialize both the wallet DB and the block-cache DB (idempotent migrations).
pub fn init_dbs(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<WriteDb> {
    std::fs::create_dir_all(wallet_dir)?;
    enable_wal(wallet_dir)?;
    let mut db_cache = open_fsblockdb(wallet_dir)?;
    let mut db_data = open_write(network, wallet_dir)?;
    init_blockmeta_db(&mut db_cache)
        .map_err(|e| anyhow::anyhow!("initializing block-cache db: {e}"))?;
    init_wallet_db(&mut db_data, None)?;
    Ok(db_data)
}

/// Put the wallet DB into WAL journal mode (a persistent, per-database setting) so RPC read
/// connections get consistent snapshots without blocking on the sync writer.
fn enable_wal(wallet_dir: &Path) -> anyhow::Result<()> {
    let conn = rusqlite::Connection::open(data_db_path(wallet_dir))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    // `PRAGMA journal_mode=WAL` returns the resulting mode as a row; ignore it.
    conn.query_row("PRAGMA journal_mode=WAL;", [], |_| Ok(()))?;
    Ok(())
}
