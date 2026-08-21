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

pub fn data_db_path(engine_dir: &Path) -> PathBuf {
    engine_dir.join(DATA_DB)
}

pub fn block_path(engine_dir: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&engine_dir.join(BLOCKS_FOLDER))
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
pub fn open_write(network: ZNetwork, engine_dir: &Path) -> anyhow::Result<WriteDb> {
    open_write_with_gap_limit(network, engine_dir, None)
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
    engine_dir: &Path,
    external_gap_limit: Option<u32>,
) -> anyhow::Result<WriteDb> {
    let conn = rusqlite::Connection::open(data_db_path(engine_dir))?;
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
pub fn open_read(network: ZNetwork, engine_dir: &Path) -> anyhow::Result<ReadDb> {
    Ok(WalletDb::for_path(
        data_db_path(engine_dir),
        network,
        (),
        (),
    )?)
}

/// Open the compact-block cache.
pub fn open_fsblockdb(engine_dir: &Path) -> anyhow::Result<FsBlockDb> {
    FsBlockDb::for_path(engine_dir).map_err(|e| anyhow::anyhow!("opening block-cache db: {e}"))
}

/// Initialize both the wallet DB and the block-cache DB (idempotent migrations).
pub fn init_dbs(network: ZNetwork, engine_dir: &Path) -> anyhow::Result<WriteDb> {
    init_dbs_with_gap_limit(network, engine_dir, None)
}

/// As [`init_dbs`], but with an explicit **external** transparent gap limit (`None` = crate
/// default). The actor and `zecd init` pass the wallet's configured `transparent_gap_limit` when
/// transparent receiving is enabled, so address generation and the restore scan use the same
/// (wider) window.
pub fn init_dbs_with_gap_limit(
    network: ZNetwork,
    engine_dir: &Path,
    external_gap_limit: Option<u32>,
) -> anyhow::Result<WriteDb> {
    std::fs::create_dir_all(engine_dir)?;
    enable_wal(engine_dir)?;
    let mut db_cache = open_fsblockdb(engine_dir)?;
    let mut db_data = open_write_with_gap_limit(network, engine_dir, external_gap_limit)?;
    init_blockmeta_db(&mut db_cache)
        .map_err(|e| anyhow::anyhow!("initializing block-cache db: {e}"))?;
    init_wallet_db(&mut db_data, None)?;
    Ok(db_data)
}

/// Put the wallet DB into WAL journal mode (a persistent, per-database setting) so RPC read
/// connections get consistent snapshots without blocking on the sync writer.
fn enable_wal(engine_dir: &Path) -> anyhow::Result<()> {
    let conn = rusqlite::Connection::open(data_db_path(engine_dir))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    // `PRAGMA journal_mode=WAL` returns the resulting mode as a row; ignore it.
    conn.query_row("PRAGMA journal_mode=WAL;", [], |_| Ok(()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exposing a single index past the gap drags the matcher's whole coverage window up with
    /// it, by a further full `gap_limit`.
    ///
    /// `rebuild_transparent_set` derives its frontier as `max(initial_scan, highest exposed + 1)`
    /// and then scans `frontier .. frontier + gap_limit`. So one address exposed at index N puts
    /// coverage at `N+1 ..= N+gap_limit` - past the recovery horizon
    /// (`initial_scan + gap_limit`), and past what a from-seed restore of the same wallet would
    /// reach. This reproduces the arithmetic against a real wallet DB so the shape is pinned
    /// rather than inferred from a log line.
    /// Live matcher coverage follows **issuance**, not the recovery horizon - and the two are
    /// deliberately different windows.
    ///
    /// `rebuild_transparent_set` anchors its frontier on *exposure* (`highest exposed + 1`) and
    /// scans a further `gap_limit` past it, so a wallet always credits receives on addresses it
    /// handed out. The **recovery horizon** (`transparent_initial_scan + transparent_gap_limit`)
    /// is a different bound: it follows *funding* (librustzcash's `find_gap_start` keys on
    /// `first_use_height`; exposure does not anchor it) and is what limits a from-seed restore.
    ///
    /// So live coverage can legitimately extend past the recovery horizon, and does exactly when
    /// the operator has issued past it - which requires `[pools]
    /// transparent_allow_beyond_recovery_window` (default `true`); with it `false`,
    /// `getnewaddress` returns `-4` at the horizon instead. That issuance already warns the
    /// address may be UNRECOVERABLE from seed; this pins the matcher's half of the same story so
    /// the wider window can't be mistaken for a restore guarantee again.
    #[test]
    fn live_matcher_coverage_follows_issuance_not_the_recovery_horizon() {
        use bip0039::{English, Mnemonic};
        use secrecy::SecretVec;
        use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};
        use zcash_client_backend::wallet::Exposure;
        use zcash_keys::keys::UnifiedAddressRequest;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::consensus::BlockHeight;
        use zip32::DiversifierIndex;

        const GAP: u32 = 3;
        const EXPOSE_AT: u32 = 5;
        const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
             midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
             moment stage";

        let dir = tempfile::tempdir().unwrap();
        let net = crate::network::regtest();
        let mut db = init_dbs_with_gap_limit(net, dir.path(), Some(GAP)).expect("init dbs");
        let seed = SecretVec::new(
            <Mnemonic<English>>::from_phrase(PHRASE)
                .unwrap()
                .to_seed("")
                .to_vec(),
        );
        let birthday = AccountBirthday::from_parts(
            zcash_client_backend::data_api::chain::ChainState::empty(
                BlockHeight::from_u32(0),
                BlockHash([0u8; 32]),
            ),
            None,
        );
        let account = db
            .create_account("primary", &seed, &birthday, None)
            .expect("create account")
            .0;

        // Expose exactly one index past the gap, the way beyond-gap issuance does.
        let req: UnifiedAddressRequest = crate::pools::transparent_extraction_request();
        db.get_address_for_index(account, DiversifierIndex::from(EXPOSE_AT), req)
            .expect("expose an index past the gap");

        // The frontier the matcher would derive, computed exactly as rebuild_transparent_set does.
        let external = db
            .get_transparent_receivers(account, false, false)
            .expect("external receivers");
        let mut exposed: Vec<u32> = external
            .values()
            .filter(|m| matches!(m.exposure(), Exposure::Exposed { .. }))
            .filter_map(|m| m.address_index().map(|i| i.index()))
            .collect();
        exposed.sort_unstable();
        let frontier = exposed
            .iter()
            .map(|i| i.saturating_add(1))
            .max()
            .unwrap_or(0);
        let coverage_end = frontier.saturating_add(GAP);
        // The anchored recovery horizon for this wallet: initial_scan = 0 and the committed
        // phrase's default address sits at index 0 (restore floor 1), so the horizon is
        // GAP + 1 (see `actor::recovery_horizon_for`).
        let horizon = GAP + 1;

        // The contract: coverage tracks the issuance frontier, so it reaches past the
        // recovery horizon once an address has been issued past it.
        assert_eq!(
            frontier,
            EXPOSE_AT + 1,
            "frontier follows the highest exposed index"
        );
        assert_eq!(
            coverage_end,
            frontier + GAP,
            "live coverage runs a full gap past the frontier"
        );
        assert!(
            coverage_end > horizon,
            "issuing past the horizon widens live coverage beyond it (that is the point of this \
             test); exposed={exposed:?} frontier={frontier} coverage_end={coverage_end} \
             horizon={horizon}"
        );
        // And the difference is exactly what a from-seed restore would NOT cover: such a restore
        // starts its frontier at the floor, so indices `horizon..coverage_end` are matched live
        // but are not recoverable from seed. That gap is the operator's, accepted by setting
        // transparent_allow_beyond_recovery_window (or avoided by raising
        // transparent_initial_scan).
        assert!(
            (horizon..coverage_end).contains(&8),
            "with gap {GAP} and an address issued at {EXPOSE_AT}, index 8 sits in the \
             matched-live-but-not-restorable band {horizon}..{coverage_end}"
        );
    }

    /// A from-seed restore of a seed whose **default address sits at index 0** must not
    /// materialize transparent receiving addresses beyond the configured external gap limit.
    ///
    /// This is the property `regtest_transparent_gap` asserts end-to-end (fund a high index,
    /// restore with `transparent_gap_limit = 3`, require the funds stay missed). The matcher
    /// matches against *every recorded receiver*, so if account creation wrote rows past the gap
    /// the scan would find a receive the gap limit says is unrecoverable.
    ///
    /// NB the invariant is conditional on the seed: account creation pre-generates rows up
    /// through the seed's default-address index and exposes that index (see
    /// `account_creation_anchors_the_frontier_at_the_default_address_index`), so a seed whose
    /// default address lands past the gap legitimately materializes rows beyond it. The
    /// committed development phrase's default index is 0 - asserted below so a phrase swap can't
    /// silently void the precondition - which makes this the clean-baseline half of the pair.
    ///
    /// Checked here directly and deterministically: create the account exactly as `zecd init`
    /// does for a transparent wallet (`init_dbs_with_gap_limit` + `create_account`) and read back
    /// what the external chain actually holds.
    #[test]
    fn account_creation_respects_the_configured_transparent_gap_limit() {
        use bip0039::{English, Mnemonic};
        use secrecy::SecretVec;
        use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};
        use zcash_client_backend::wallet::Exposure;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::consensus::BlockHeight;

        const GAP: u32 = 3;
        // The checked-in testnet-only development phrase (see the project docs).
        const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october              midnight culture idea mountain fame park social drip bid doctor scatter glance defy              moment stage";

        let dir = tempfile::tempdir().unwrap();
        let net = crate::network::regtest();
        let mut db = init_dbs_with_gap_limit(net, dir.path(), Some(GAP)).expect("init dbs");
        let seed_bytes = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");

        // Precondition (see the doc comment): this phrase's default address must sit at index 0,
        // or the beyond-gap assertion below stops describing a clean baseline.
        {
            use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
            let usk = UnifiedSpendingKey::from_seed(&net, &seed_bytes, zip32::AccountId::ZERO)
                .expect("derive USK");
            let (_, d_idx) = usk
                .to_unified_full_viewing_key()
                .to_unified_incoming_viewing_key()
                .find_address(
                    zip32::DiversifierIndex::new(),
                    UnifiedAddressRequest::AllAvailableKeys,
                )
                .expect("derive the default address as account creation does");
            assert_eq!(
                u32::try_from(u128::from(d_idx)),
                Ok(0),
                "the committed phrase's default-address index must be 0 for this test's \
                 invariant to hold; a different phrase needs re-checking"
            );
        }

        let seed = SecretVec::new(seed_bytes.to_vec());
        let birthday = AccountBirthday::from_parts(
            zcash_client_backend::data_api::chain::ChainState::empty(
                BlockHeight::from_u32(0),
                BlockHash([0u8; 32]),
            ),
            None,
        );
        let account = db
            .create_account("primary", &seed, &birthday, None)
            .expect("create account")
            .0;

        // External receivers only (no change chain).
        let external = db
            .get_transparent_receivers(account, false, false)
            .expect("external transparent receivers");
        let mut indices: Vec<(u32, bool)> = external
            .values()
            .filter_map(|meta| {
                meta.address_index().map(|i| {
                    (
                        i.index(),
                        matches!(meta.exposure(), Exposure::Exposed { .. }),
                    )
                })
            })
            .collect();
        indices.sort_unstable();

        let beyond: Vec<u32> = indices
            .iter()
            .map(|(i, _)| *i)
            .filter(|i| *i >= GAP)
            .collect();
        assert!(
            beyond.is_empty(),
            "account creation with transparent_gap_limit = {GAP} materialized external \
             index/indices {beyond:?} beyond the gap; the block-scan matcher matches every \
             recorded receiver, so a receive there would be recovered on a restore the gap limit \
             says must miss it. Full external chain (index, exposed): {indices:?}"
        );

        // The frontier the matcher derives (`highest exposed + 1`) must likewise stay inside the
        // window, or the lookahead starts past the gap on a wallet that has issued nothing.
        let frontier = indices
            .iter()
            .filter(|(_, exposed)| *exposed)
            .map(|(i, _)| i.saturating_add(1))
            .max()
            .unwrap_or(0);
        assert!(
            frontier <= GAP,
            "a freshly restored wallet that has issued no addresses reports a matcher frontier \
             of {frontier} with gap {GAP}; external chain (index, exposed): {indices:?}"
        );
    }

    /// Account creation anchors the transparent frontier at the **default address's** index -
    /// a per-seed value, not always 0 - and every restore of the seed reproduces it exactly.
    ///
    /// `add_account` (upstream) always derives and exposes the account's default Unified
    /// Address with `UnifiedAddressRequest::AllAvailableKeys`, whose diversifier index is the
    /// first index valid for every receiver the key has. For a key with a Sapling component
    /// that is the first Sapling-valid index: geometric with p ~ 1/2, so it is 0 for only about
    /// half of all seeds (>= 3 for ~1 in 8, >= 5 for ~1 in 32). The exposed transparent
    /// receiver at that index is what `rebuild_transparent_set` derives its frontier from, so a
    /// freshly created (or freshly restored) wallet legitimately reports `lookahead_from =
    /// default index + 1` - the per-run "frontier well above 0 on a fresh restore" that
    /// intermittently tripped `regtest_transparent_gap` (frontiers 5/6/10, one per fresh CI
    /// mnemonic) before the recovery horizon was anchored at the same floor.
    ///
    /// Pinned here with a seed whose default index (6) lands *past* the configured gap of 3:
    /// account creation pre-generates rows `0..=6` (so indices beyond the gap DO get rows -
    /// upstream's "pre-generate prior to the default address" pass), exposes only index 6, and
    /// a second creation from the same seed reproduces the identical state - which is why this
    /// anchor is deterministic per seed, keeps restores of one seed consistent with each other,
    /// and belongs *inside* the recovery horizon (`actor::recovery_horizon_for`) rather than
    /// being reported as unrestorable.
    #[test]
    fn account_creation_anchors_the_frontier_at_the_default_address_index() {
        use secrecy::SecretVec;
        use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};
        use zcash_client_backend::wallet::Exposure;
        use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::consensus::BlockHeight;

        const GAP: u32 = 3;
        // A fixed seed whose default-address diversifier index is 6 (first Sapling-valid index
        // for this key; verified below rather than trusted).
        const SEED_BYTE: u8 = 12;
        const DEFAULT_INDEX: u32 = 6;

        let net = crate::network::regtest();
        let usk = UnifiedSpendingKey::from_seed(&net, &[SEED_BYTE; 64], zip32::AccountId::ZERO)
            .expect("derive USK");
        let (default_ua, d_idx) = usk
            .to_unified_full_viewing_key()
            .to_unified_incoming_viewing_key()
            .find_address(
                zip32::DiversifierIndex::new(),
                UnifiedAddressRequest::AllAvailableKeys,
            )
            .expect("derive the default address as account creation does");
        assert_eq!(
            u32::try_from(u128::from(d_idx)),
            Ok(DEFAULT_INDEX),
            "the fixture seed's default-address index"
        );
        assert!(
            default_ua.transparent().is_some(),
            "the default UA carries the p2pkh receiver that gets exposed"
        );

        // Create the account twice from the same seed (two independent "restores") and read
        // back the external transparent chain each time.
        let external_chain = || {
            let dir = tempfile::tempdir().unwrap();
            let mut db = init_dbs_with_gap_limit(net, dir.path(), Some(GAP)).expect("init dbs");
            let seed = SecretVec::new(vec![SEED_BYTE; 64]);
            let birthday = AccountBirthday::from_parts(
                zcash_client_backend::data_api::chain::ChainState::empty(
                    BlockHeight::from_u32(0),
                    BlockHash([0u8; 32]),
                ),
                None,
            );
            let account = db
                .create_account("primary", &seed, &birthday, None)
                .expect("create account")
                .0;
            let external = db
                .get_transparent_receivers(account, false, false)
                .expect("external receivers");
            let mut rows: Vec<(u32, bool)> = external
                .values()
                .filter_map(|m| {
                    m.address_index()
                        .map(|i| (i.index(), matches!(m.exposure(), Exposure::Exposed { .. })))
                })
                .collect();
            rows.sort_unstable();
            rows
        };
        let rows = external_chain();

        // Rows run 0..=default index (exposure only at the default index), so indices past the
        // gap ARE materialized - the matcher matches every row, and a restore reproduces them.
        let expected: Vec<(u32, bool)> = (0..=DEFAULT_INDEX)
            .map(|i| (i, i == DEFAULT_INDEX))
            .collect();
        assert_eq!(
            rows, expected,
            "account creation materializes rows through the default index and exposes only it"
        );
        let frontier = rows
            .iter()
            .filter(|(_, exposed)| *exposed)
            .map(|(i, _)| i.saturating_add(1))
            .max()
            .unwrap_or(0);
        assert_eq!(
            frontier,
            DEFAULT_INDEX + 1,
            "the matcher frontier starts one past the default address"
        );

        // Restore determinism: a second creation from the same seed reproduces the identical
        // chain, so the anchor never diverges between two restores of one seed.
        assert_eq!(
            external_chain(),
            rows,
            "a second create-from-seed reproduces the same external chain"
        );
    }

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
