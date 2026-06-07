//! Funded regtest end-to-end: get real Orchard funds into `zecd` and verify it sees them.
//!
//! Regtest can't mine a coinbase directly into an Orchard note that `zecd` (Orchard-only receive)
//! would scan, so we fund it the way the protocol allows: mine a **transparent** coinbase to a
//! funding wallet (`zcash-devtool`), let it mature (100 blocks), **shield** it into Orchard, then
//! **send** Orchard funds to `zecd`'s unified address.
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set (see
//! README.md). This is the Phase 1 deliverable: prove funded receive works end to end. Phase 2
//! builds the full RPC coverage on top of a funded wallet.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// Coinbase maturity is 100 blocks; mine one past that so the height-1 coinbase is spendable.
const MATURITY_BLOCKS: u32 = 101;
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
/// Generous: lightwalletd ingestion + zecd scan + Orchard proving.
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_funded_orchard_receive() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_funded_orchard_receive: set ZEBRAD_BIN, LIGHTWALLETD_BIN and DEVTOOL_BIN \
             to run the funded e2e (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // 1. Bring up a throwaway node just long enough to initialise the funding wallet and learn the
    //    address its coinbase must be mined to (chicken-and-egg: the wallet is created against a
    //    running chain, but zebra needs the address at launch).
    let funder = {
        let zebrad_tmp = Zebrad::start(&zebrad_bin).await.expect("start temp zebrad");
        let lwd_tmp = Lightwalletd::start(&lwd_bin, zebrad_tmp.rpc_port)
            .await
            .expect("start temp lightwalletd");
        Funder::init(&devtool_bin, lwd_tmp.grpc_port).expect("initialise funding wallet")
        // temp nodes are dropped (killed) here; the funder wallet on disk persists.
    };
    let funder_ua = funder.unified_address().expect("funder unified address");

    // 2. Real node mining the coinbase to the funder, behind a fresh lightwalletd.
    let zebrad = Zebrad::start_with_miner(&zebrad_bin, &funder_ua)
        .await
        .expect("start zebrad mining to the funder");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");

    // 3. Mine past coinbase maturity, then shield the transparent coinbase into Orchard.
    zebrad
        .generate_blocks(MATURITY_BLOCKS)
        .await
        .expect("mine to coinbase maturity");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(2).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 4. zecd against the same lightwalletd; get its Orchard unified address.
    let cfg = ZecdConfig {
        lightwalletd_port: lwd.grpc_port,
        rpc_port: pick_port().expect("pick zecd rpc port"),
        rpc_user: "user".to_string(),
        rpc_password: "pass".to_string(),
    };
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against regtest lightwalletd");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();
    assert!(
        zecd_ua.starts_with("uregtest1"),
        "expected a uregtest1 address, got {zecd_ua}"
    );

    // 5. Fund zecd: send Orchard funds from the funder to zecd's UA, then confirm.
    funder
        .send(lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS)
        .expect("send Orchard funds to zecd");
    zebrad
        .generate_blocks(2)
        .await
        .expect("confirm funding send");

    // 6. zecd scans the note and reports the balance.
    let deadline = Instant::now() + FUND_TIMEOUT;
    let balance = loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal > 0.0 {
            break bal;
        }
        if Instant::now() >= deadline {
            panic!("zecd did not see the funded Orchard note within {FUND_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    // ~1 ZEC received (the funder paid the fee), give or take change semantics.
    assert!(
        balance > 0.0,
        "zecd should have a positive Orchard balance, got {balance}"
    );

    // The receive shows up in history as a `receive` transaction.
    let txs = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let txs = txs.as_array().expect("listtransactions is an array");
    assert!(
        !txs.is_empty(),
        "expected at least one transaction in zecd history"
    );
    assert!(
        txs.iter()
            .any(|t| t.get("category").and_then(|c| c.as_str()) == Some("receive")),
        "expected a receive in zecd history: {txs:?}"
    );
}
