//! Opening and initializing the per-wallet `zcash_client_sqlite` databases.
//! Ported from `zcash-devtool/src/data.rs`.

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;

use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::chain::BlockMeta;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};
use zcash_keys::keys::transparent::gap_limits::GapLimits;

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
///
/// The writer connection runs `PRAGMA synchronous = NORMAL`. In WAL mode this is
/// **corruption-safe**: the append-only WAL means a power loss can only truncate the unsynced
/// tail of the log (recovery replays up to the last intact frame), never corrupt the database
/// file, and checkpoints still fsync before writing back to the main db. What it trades is
/// durability of the last few committed writes - which for zecd is nearly free, because
/// everything in this DB (scanned blocks, decrypted notes, the clock-derived diversifier
/// cursor, even an authored-and-broadcast send recovered via the OVK enhancement) is
/// re-derivable from the chain by resuming the scan. The win scales with fsync latency:
/// marginal on local SSD, a multiple-x on exchange-grade networked or encrypted block storage
/// where an fsync is 5-20 ms and `FULL` would dominate the write path.
///
/// `synchronous` is **per-connection** (unlike the persistent `journal_mode`), so it must be
/// set here on the connection `WalletDb` will own - hence `from_connection` rather than
/// `for_path` (the writer is opened once and lives for the actor's lifetime, so set-once is
/// enough). Read connections (`open_read`) never commit, so `synchronous` there is a no-op and
/// is left untouched.
pub fn open_write(network: ZNetwork, wallet_dir: &Path) -> anyhow::Result<WriteDb> {
    open_write_with_gap_limit(network, wallet_dir, None)
}

/// Apply the write-path PRAGMAs (and the array vtab module `WalletDb` requires) to a
/// freshly-opened writer connection. Split out so it is unit-testable against a temp DB.
fn configure_writer_conn(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    // `WalletDb::from_connection` requires the array vtab module that `for_path` loads itself.
    rusqlite::vtab::array::load_module(conn)?;
    // WAL is a persistent per-database setting (also established at init in `enable_wal`), but
    // reassert it on this exact connection so the NORMAL+WAL corruption-safety pairing is
    // guaranteed together: `synchronous = NORMAL` is *not* corruption-safe under a rollback
    // journal. `journal_mode=WAL` returns the resulting mode as a row, which `execute_batch`
    // discards.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
}

/// librustzcash's default transparent gap limits for the internal (change) and ephemeral (TEX)
/// scopes. zecd only ever varies the *external* gap limit (the user-facing receiving chain), so
/// these mirror `zcash_keys::keys::transparent::gap_limits::GapLimits::default()`.
const DEFAULT_INTERNAL_GAP: u32 = 5;
const DEFAULT_EPHEMERAL_GAP: u32 = 10;

/// Open the wallet DB for writing, optionally overriding the **external** transparent gap limit
/// (`Some(n)` widens the window librustzcash scans/derives on the receiving chain; `None` keeps
/// the crate default of 10). A larger external gap limit is how a stateless restore rediscovers
/// transparent funds across many pre-generated-but-unfunded addresses. The writer connection is
/// configured (WAL + `synchronous = NORMAL`) the same way as [`open_write`].
pub fn open_write_with_gap_limit(
    network: ZNetwork,
    wallet_dir: &Path,
    external_gap_limit: Option<u32>,
) -> anyhow::Result<WriteDb> {
    let conn = rusqlite::Connection::open(data_db_path(wallet_dir))?;
    configure_writer_conn(&conn)?;
    let db = WalletDb::from_connection(conn, network, SystemClock, OsRng);
    Ok(match external_gap_limit {
        Some(n) => db.with_gap_limits(GapLimits::new(
            n,
            DEFAULT_INTERNAL_GAP,
            DEFAULT_EPHEMERAL_GAP,
        )),
        None => db,
    })
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
    init_dbs_with_gap_limit(network, wallet_dir, None)
}

/// As [`init_dbs`], but with an explicit **external** transparent gap limit (`None` = crate
/// default). The actor and `zecd init` pass the wallet's configured `transparent_gap_limit` when
/// transparent receiving is enabled, so address generation and the restore scan use the same
/// (wider) window.
pub fn init_dbs_with_gap_limit(
    network: ZNetwork,
    wallet_dir: &Path,
    external_gap_limit: Option<u32>,
) -> anyhow::Result<WriteDb> {
    std::fs::create_dir_all(wallet_dir)?;
    enable_wal(wallet_dir)?;
    let mut db_cache = open_fsblockdb(wallet_dir)?;
    let mut db_data = open_write_with_gap_limit(network, wallet_dir, external_gap_limit)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The writer connection must run in WAL mode with `synchronous = NORMAL`. The two go
    /// together: NORMAL is only corruption-safe under WAL, so a future refactor must not land
    /// one without the other. (`synchronous` is per-connection, so this is asserted on the same
    /// connection that `configure_writer_conn` set it on - a fresh connection would not reflect
    /// it.)
    #[test]
    fn writer_connection_uses_wal_and_normal_synchronous() {
        let dir = tempfile::tempdir().unwrap();
        let conn = rusqlite::Connection::open(dir.path().join(DATA_DB)).unwrap();
        configure_writer_conn(&conn).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");

        // PRAGMA synchronous reports the numeric level: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA.
        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(synchronous, 1, "writer must run synchronous=NORMAL");
    }
}
