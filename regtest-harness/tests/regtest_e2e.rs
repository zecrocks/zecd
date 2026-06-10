//! End-to-end regtest test: zebra (Regtest) + lightwalletd + the real `zecd` daemon.
//!
//! Skips cleanly when the node binaries aren't provisioned (so plain `cargo test` and the
//! build-only CI path still validate that the harness compiles). Provide `ZEBRAD_BIN` and
//! `LIGHTWALLETD_BIN` to run the full flow - see README.md.

use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{pick_port, resolve_bin, Lightwalletd, Zebrad, Zecd, ZecdConfig};

/// Blocks mined before launching zecd. Regtest mining is cheap (PoW disabled).
const INITIAL_BLOCKS: u32 = 10;
/// Generous: lightwalletd ingestion + zecd scan over a fresh regtest chain.
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn regtest_end_to_end() {
    let (Some(zebrad_bin), Some(lightwalletd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_end_to_end: set ZEBRAD_BIN and LIGHTWALLETD_BIN to run the live e2e \
             (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // 1. zebra Regtest node, then mine the initial chain (getblocktemplate/submitblock).
    let zebrad = Zebrad::start(&zebrad_bin)
        .await
        .expect("launch zebrad regtest");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial regtest blocks");

    // 2. lightwalletd in front of zebra (ingests the mined chain).
    let lightwalletd = Lightwalletd::start(&lightwalletd_bin, zebrad.rpc_port)
        .await
        .expect("launch lightwalletd");

    // 3. zecd against lightwalletd (init retries until lightwalletd has caught up).
    let cfg = ZecdConfig::new(
        lightwalletd.grpc_port,
        pick_port().expect("pick zecd rpc port"),
    );
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against regtest lightwalletd");
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

    // encryptwallet flips it to the Bitcoin-Core encrypted state: the wallet locks (send ->
    // -13; the seed check precedes input selection so no funds are needed), a wrong
    // passphrase is rejected (-14), and the real one unlocks - back to failing on funds (-6).
    zecd.call("encryptwallet", json!(["regtest-pass"]))
        .await
        .expect("encryptwallet");
    let err = zecd
        .call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect_err("a locked wallet must refuse to send");
    assert_eq!(
        err.code(),
        Some(-13),
        "expected unlock-needed (-13), got: {err}"
    );
    let err = zecd
        .call("walletpassphrase", json!(["wrong-pass", 60]))
        .await
        .expect_err("a wrong passphrase must be rejected");
    assert_eq!(
        err.code(),
        Some(-14),
        "expected passphrase-incorrect (-14), got: {err}"
    );
    zecd.call("walletpassphrase", json!(["regtest-pass", 60]))
        .await
        .expect("the real passphrase unlocks");
    let err = zecd
        .call("sendtoaddress", json!([addr, 1.0]))
        .await
        .expect_err("still no funds after unlocking");
    assert_eq!(
        err.code(),
        Some(-6),
        "after unlock the send fails on funds again (-6), got: {err}"
    );

    // Mining more blocks advances zecd's view by exactly that many.
    zebrad.generate_blocks(5).await.expect("mine 5 more");
    zecd.wait_until_synced(height0 + 5, SYNC_TIMEOUT)
        .await
        .expect("zecd follows the new blocks");
    assert_eq!(
        zecd.block_count().await.expect("getblockcount"),
        height0 + 5
    );
}
