//! End-to-end regtest test: zebra (Regtest) + the real `zecd` daemon.
//!
//! Skips cleanly when the node binary isn't provisioned (so plain `cargo test` and the
//! build-only CI path still validate that the harness compiles). Provide `ZEBRAD_BIN` to run
//! the full flow.

use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{pick_port, resolve_node_bin, RegtestNode, Zebrad, Zecd, ZecdConfig};

/// Blocks mined before launching zecd. Regtest mining is cheap (PoW disabled).
const INITIAL_BLOCKS: u32 = 10;
/// Generous: zecd scan over a fresh regtest chain.
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn regtest_end_to_end() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_end_to_end: set {} to run the live e2e. The harness still compiled and \
             linked.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // 1. zebrad-dialect Regtest node (zebra or zakura), then mine the initial chain
    //    (getblocktemplate/submitblock).
    let zebrad = Zebrad::start(&zebrad_bin)
        .await
        .expect("launch zebrad regtest");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial regtest blocks");

    // 2. zecd against zebra's JSON-RPC.
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let mut zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against regtest zebra");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans to the regtest tip");

    // ---- zecd RPC assertions ----

    // Chain identity. Capture the synced height rather than assuming an absolute value (how the
    // regtest genesis maps to a tip height is an implementation detail); `blocks` is the
    // fully-scanned height.
    let info = zecd
        .call("getblockchaininfo", json!([]))
        .await
        .expect("getblockchaininfo");
    assert_eq!(info["chain"], "regtest", "getblockchaininfo.chain");
    let height0 = info["blocks"].as_u64().expect("blocks is a number");
    assert!(
        height0 >= INITIAL_BLOCKS as u64,
        "zecd should have scanned at least the {INITIAL_BLOCKS} mined blocks (got {height0})"
    );

    // Orchard-only receive address: unified, regtest-encoded.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().expect("address is a string");
    assert!(
        addr.starts_with("uregtest1"),
        "expected a uregtest1 unified address, got {addr}"
    );

    let validated = zecd
        .call("validateaddress", json!([addr]))
        .await
        .expect("validateaddress");
    assert_eq!(
        validated["isvalid"], true,
        "validateaddress.isvalid for our own address"
    );

    // Empty wallet: zero balance, no history, no notes.
    let balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(
        balance.as_f64(),
        Some(0.0),
        "fresh wallet balance should be 0"
    );
    let txs = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert_eq!(
        txs.as_array().map(|a| a.len()),
        Some(0),
        "no transactions yet"
    );

    // Spending with no funds → Bitcoin Core's insufficient-funds code (-6).
    let err = zecd
        .call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect_err("sendtoaddress with an empty wallet must fail");
    assert_eq!(
        err.code(),
        Some(-6),
        "expected insufficient-funds (-6), got: {err}"
    );

    // The wallet is unencrypted (age-identity model): the passphrase RPCs reject with -15,
    // exactly like bitcoind running with an unencrypted wallet.
    let err = zecd
        .call("walletlock", json!([]))
        .await
        .expect_err("walletlock on an unencrypted wallet must fail");
    assert_eq!(err.code(), Some(-15), "expected -15, got: {err}");
    let err = zecd
        .call("walletpassphrase", json!(["x", 60]))
        .await
        .expect_err("walletpassphrase on an unencrypted wallet must fail");
    assert_eq!(err.code(), Some(-15), "expected -15, got: {err}");

    // Mining more blocks advances zecd's view by exactly that many.
    zebrad.generate_blocks(5).await.expect("mine 5 more");
    zecd.wait_until_synced(height0 + 5, SYNC_TIMEOUT)
        .await
        .expect("zecd follows the new blocks");
    assert_eq!(
        zecd.block_count().await.expect("getblockcount"),
        height0 + 5
    );

    // ---- data directory layout migration ----
    // A data directory written by an older zecd keeps librustzcash's databases at the root of
    // each wallet directory; this build keeps them under `<wallet>/zec/lrz/`, with `keys.toml`
    // still at the wallet root. Recreate the older layout on a real, scanned wallet and
    // restart: the daemon must move the databases and come back up on that same wallet.
    let addr = addr.to_string();
    let wallet = zecd.wallet_dir("default");
    let engine = zecd.engine_dir("default");
    zecd.stop_keeping_datadir().await.expect("stop zecd");
    for artifact in std::fs::read_dir(&engine).expect("read the engine dir") {
        let path = artifact.expect("engine dir entry").path();
        let name = path.file_name().expect("artifact name").to_owned();
        std::fs::rename(&path, wallet.join(&name)).expect("put the databases back at the root");
    }
    std::fs::remove_dir_all(wallet.join("zec")).expect("remove the now-empty coin dir");

    zecd.respawn()
        .await
        .expect("zecd starts on a data directory in the older layout");
    zecd.wait_until_synced(height0 + 5, SYNC_TIMEOUT)
        .await
        .expect("the migrated wallet syncs");
    assert!(
        engine.join("data.sqlite").is_file(),
        "the wallet database moved to {}",
        engine.display()
    );
    assert!(
        !wallet.join("data.sqlite").exists(),
        "the database is moved, not copied"
    );
    assert!(
        wallet.join("keys.toml").is_file(),
        "keys.toml stays at the wallet root, above the per-coin directories"
    );
    let info = zecd
        .call("getaddressinfo", json!([addr]))
        .await
        .expect("getaddressinfo after the layout migration");
    assert_eq!(
        info["ismine"], true,
        "the migrated wallet is the same wallet - it still owns {addr}"
    );
}
