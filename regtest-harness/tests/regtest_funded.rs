//! Funded regtest end-to-end: get real Orchard funds into `zecd` and verify it sees them.
//!
//! Regtest can't mine a coinbase directly into an Orchard note that `zecd` (Orchard-only receive)
//! would scan, so we fund it the way the protocol allows: mine a **transparent** coinbase to a
//! funding wallet (`zcash-devtool`), let it mature (100 blocks), **shield** it into Orchard, then
//! **send** Orchard funds to `zecd`'s unified address.
//!
//! Everything runs on a **single chain**: we derive the funder's transparent address *offline*
//! (`devtool wallet derive-address`) and mine straight to it, so the funder's wallet birthday
//! anchor is taken from the same chain it spends on (a throwaway "discover the address" chain would
//! hand the wallet a wrong note-commitment anchor and the shield/send proofs would be invalid).
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set (see
//! README.md). Phase 1 deliverable: prove funded receive works end to end.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// Blocks mined up front. Coinbase maturity is 100, so with the tip here the early coinbases
/// (heights ~1..10) are spendable, giving the funder plenty to shield.
const INITIAL_MINE: u32 = 110;
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

    // 1. Learn the funder's transparent address offline (no chain yet) so zebra can mine its
    //    coinbase straight to it - keeping the whole flow on one chain.
    let funder_taddr = Funder::derive_transparent_address(&devtool_bin)
        .expect("derive funder transparent address");

    // 2. Single chain: zebra mines the coinbase to the funder, behind lightwalletd.
    let zebrad = Zebrad::start_with_miner(&zebrad_bin, &funder_taddr)
        .await
        .expect("start zebrad mining to the funder");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");

    // 3. Mine past coinbase maturity.
    zebrad
        .generate_blocks(INITIAL_MINE)
        .await
        .expect("mine the initial chain");

    // 4. Initialise the funder against THIS chain, then shield its matured transparent coinbase
    //    into Orchard.
    let funder = Funder::init(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    // shield only selects mature coinbases (zcash_client_sqlite's coinbase-maturity filter), so the
    // broadcast is accepted without any extra maturity buffer.
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(2).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 5. zecd against the same lightwalletd; get its Orchard unified address.
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

    // 6. Fund zecd: send Orchard funds from the funder to zecd's UA, then confirm.
    funder
        .send(lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS)
        .expect("send Orchard funds to zecd");
    zebrad
        .generate_blocks(2)
        .await
        .expect("confirm funding send");

    // 7. zecd scans the note and reports the balance.
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
