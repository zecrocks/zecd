//! End-to-end test of the data-directory layout migration (`src/migrate.rs`) on a **funded**
//! wallet: the flow an operator upgrading across this change actually experiences.
//!
//! Older zecd kept librustzcash's databases at the root of each wallet directory, beside
//! `keys.toml`. They now live one coin and one engine deeper - `<wallet>/zec/lrz/` - while
//! `keys.toml` stays at the wallet root, because the seed it wraps serves every coin and is the
//! one file here that no chain can rebuild. The daemon performs that move once, under the
//! datadir lock, before anything opens a wallet.
//!
//! Why funded rather than a bare start/stop: if the move simply failed to happen, the daemon
//! would find no database at the new path and rebuild an empty one from `keys.toml`, then
//! rescan - which on a *fundless* wallet is indistinguishable from success. What only a funded
//! wallet can show is that the migration preserved the *data* - balance, transaction history, a
//! received memo, and the compact-block cache - and that it did so without a rescan.
//!
//! Three properties, in order:
//!
//!   1. **Refusal.** The same database in both places is ambiguous - zecd must refuse to start
//!      and say so, leaving both copies intact, rather than pick one.
//!   2. **Migration.** With only the old layout present, the daemon moves the databases and
//!      comes back up on the same wallet, funds and history intact.
//!   3. **Idempotence.** A second restart migrates nothing.
//!
//! Standard tier, zebra-only (no lightwalletd needed - the funder talks `zebra://`). Skips
//! cleanly unless the node binary is provisioned.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use zecd_regtest_harness::{
    pick_port, resolve_node_bin, start_funded_chain, RegtestNode, Zebrad, Zecd, ZecdConfig,
};

/// Fund the wallet with 2 ZEC - enough that a lost database is unmistakable in the balance.
const FUND_ZATOSHIS: u64 = 200_000_000;
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
/// Carried on the funding payment. A memo lives only in the wallet database (compact blocks
/// carry none), so seeing it again after the move is direct evidence the database came along.
const RECEIVE_MEMO: &str = "layout migration";
/// Blocks mined to confirm the funding payment.
const CONFIRM_BLOCKS: u32 = 12;

/// zebrad's current best height (the harness mines via `generate`; this reads the tip back).
async fn tip(zebrad: &Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebrad getblockcount")
        .as_u64()
        .expect("getblockcount height")
}

/// The durable contents of an engine directory: both databases and the compact-block cache
/// directory. Everything a "move the wallet database and forget the rest" implementation could
/// silently drop.
///
/// Deliberately not the raw directory listing: SQLite's `-wal`/`-shm` sidecars come and go
/// across a clean shutdown, so comparing those would test the journal, not the migration. Nor
/// the *contents* of `blocks/` - the scanner deletes each batch's compact blocks as it applies
/// them, so a caught-up wallet's cache is legitimately empty.
fn durable_contents(engine_dir: &Path) -> Vec<String> {
    ["data.sqlite", "blockmeta.sqlite", "blocks"]
        .iter()
        .filter(|name| engine_dir.join(name).exists())
        .map(|name| name.to_string())
        .collect()
}

/// Move everything in `from` into `to`, creating `to`. Used to put a scanned wallet back into
/// the pre-`zec/lrz/` layout the migration has to recognise.
fn move_dir_contents(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create the destination directory");
    for entry in std::fs::read_dir(from).expect("read the source directory") {
        let path = entry.expect("directory entry").path();
        let name = path.file_name().expect("entry name").to_owned();
        std::fs::rename(&path, to.join(&name)).expect("move a wallet artifact");
    }
}

/// The wallet's own view of itself, as the migration must preserve it: confirmed balance, the
/// funding transaction, and the memo on it.
async fn wallet_state(zecd: &Zecd, txid: &str) -> (f64, Value) {
    let balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("getbalance is a number");
    let tx = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction on the funding payment");
    (balance, tx)
}

/// The `memoStr` of a `gettransaction`'s receive detail (zcashd's `z_viewtransaction` naming).
fn received_memo(tx: &Value) -> Option<String> {
    tx["details"]
        .as_array()?
        .iter()
        .find(|d| d["category"] == "receive")?["memoStr"]
        .as_str()
        .map(str::to_string)
}

#[tokio::test]
async fn regtest_data_directory_layout_migration() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_data_directory_layout_migration: set {} to run the live e2e. The \
             harness still compiled and linked.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // ---- 1. A funded wallet with history worth preserving ----

    let (zebrad, funder) = start_funded_chain(&zebrad_bin)
        .await
        .expect("bring up a funded regtest chain");

    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let mut zecd = Zecd::start(&cfg).await.expect("start zecd");
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("address string")
        .to_string();

    funder
        .send_with_memo(&addr, FUND_ZATOSHIS, Some(RECEIVE_MEMO))
        .await
        .expect("fund zecd with a memo'd payment");
    let target = tip(&zebrad).await + CONFIRM_BLOCKS as u64;
    zebrad
        .generate_blocks(CONFIRM_BLOCKS)
        .await
        .expect("confirm the funding payment");
    zecd.wait_until_synced(target, FUND_TIMEOUT)
        .await
        .expect("zecd scans the funding payment");

    // Everything the migration has to carry across, recorded from the running daemon.
    let txid = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions")
        .as_array()
        .and_then(|txs| {
            txs.iter()
                .find(|t| t["category"] == "receive")
                .and_then(|t| t["txid"].as_str())
                .map(str::to_string)
        })
        .expect("the funding receive is in the history");
    let (balance_before, tx_before) = wallet_state(&zecd, &txid).await;
    let height_before = zecd.block_count().await.expect("getblockcount");
    assert!(
        balance_before > 0.0,
        "the wallet must actually hold the funds before the migration (got {balance_before})"
    );
    assert_eq!(
        received_memo(&tx_before).as_deref(),
        Some(RECEIVE_MEMO),
        "the received memo is recorded before the migration: {tx_before}"
    );

    let wallet = zecd.wallet_dir("default");
    let engine = zecd.engine_dir("default");
    let contents_before = durable_contents(&engine);
    assert_eq!(
        contents_before,
        vec!["data.sqlite", "blockmeta.sqlite", "blocks"],
        "a scanned engine directory holds all three before the move"
    );

    // ---- 2. Put the databases back at the wallet root, as an older zecd left them ----

    zecd.stop_keeping_datadir().await.expect("stop zecd");
    move_dir_contents(&engine, &wallet);
    std::fs::remove_dir_all(wallet.join("zec")).expect("remove the now-empty coin directory");
    assert!(
        wallet.join("keys.toml").is_file(),
        "keys.toml was already at the wallet root and stays there in both layouts"
    );

    // ---- 3. Refusal: the same database in both places stops startup, keeping both copies ----

    // The shape an operator produces by copying a wallet by hand, or by half-finishing this move
    // themselves. Which database is authoritative is not zecd's call to make.
    std::fs::create_dir_all(&engine).expect("create the conflicting directory");
    std::fs::copy(wallet.join("data.sqlite"), engine.join("data.sqlite"))
        .expect("plant a second copy of the database");

    let stderr = zecd
        .respawn_expect_startup_failure()
        .await
        .expect("zecd must refuse to start with the same database in both layouts");
    assert!(
        stderr.contains("data.sqlite both at"),
        "the refusal must name the ambiguity, got:\n{stderr}"
    );
    assert!(
        wallet.join("data.sqlite").is_file() && engine.join("data.sqlite").is_file(),
        "a refusal deletes nothing: both copies are still on disk"
    );

    std::fs::remove_dir_all(wallet.join("zec")).expect("remove the conflicting copy");

    // ---- 4. Migration: the daemon moves the databases and comes back up on them ----

    zecd.respawn()
        .await
        .expect("zecd starts on a data directory in the older layout");

    assert_eq!(
        durable_contents(&engine),
        contents_before,
        "every durable file moved into the engine directory, not just the wallet database"
    );
    for artifact in &contents_before {
        assert!(
            !wallet.join(artifact).exists(),
            "{artifact} is moved, not copied"
        );
    }
    assert!(
        wallet.join("keys.toml").is_file(),
        "keys.toml stays at the wallet root, above the per-coin directories"
    );

    // No blocks were mined across the restart, so a wallet that had to rebuild itself from
    // keys.toml would be visible here: a rescan from the birthday, an empty balance, and no
    // history for a transaction it has not re-scanned yet.
    let (balance_after, tx_after) = wallet_state(&zecd, &txid).await;
    assert_eq!(
        balance_after, balance_before,
        "the balance survived the migration unchanged"
    );
    assert_eq!(
        received_memo(&tx_after).as_deref(),
        Some(RECEIVE_MEMO),
        "the received memo survived the migration: {tx_after}"
    );
    assert_eq!(
        zecd.block_count().await.expect("getblockcount"),
        height_before,
        "the migrated wallet resumed at its scanned height rather than rescanning"
    );
    let info = zecd
        .call("getaddressinfo", json!([addr]))
        .await
        .expect("getaddressinfo after the migration");
    assert_eq!(
        info["ismine"], true,
        "the migrated wallet is the same wallet - it still owns {addr}"
    );

    // ---- 5. Idempotence: a second start migrates nothing ----

    zecd.stop_keeping_datadir()
        .await
        .expect("stop the migrated zecd");
    zecd.respawn()
        .await
        .expect("zecd restarts on the migrated data directory");
    let (balance_again, _) = wallet_state(&zecd, &txid).await;
    assert_eq!(
        balance_again, balance_before,
        "a second start leaves the migrated wallet alone"
    );
    assert!(
        !wallet.join("data.sqlite").exists(),
        "nothing reappeared at the old path"
    );
    assert_eq!(
        durable_contents(&engine),
        contents_before,
        "the second start left the engine directory exactly as it found it"
    );
}
