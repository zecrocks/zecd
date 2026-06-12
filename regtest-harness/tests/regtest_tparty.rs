//! Funded regtest end-to-end for `tparty`: transparent deposits auto-shield.
//!
//! The chain setup mirrors `regtest_funded.rs`: mine a transparent coinbase to a funding
//! wallet (zcash-devtool), mature it, shield it into Orchard - giving the funder spendable
//! shielded funds. The tparty-specific flow then begins: tparty hands out **t-addresses**,
//! the funder pays one (an ordinary Orchard→transparent send, exactly what a customer
//! deposit looks like), and once the deposit confirms tparty must - with no further
//! prompting - discover the transparent UTXO via lightwalletd, build a shielding
//! transaction into its own internal Orchard receiver, and broadcast it. The test then
//! watches the deposit-facing RPC surface tell that story: `getreceivedbyaddress` credits
//! the t-address, `listtransactions` shows the receive, `getbalance` (unshielded funds)
//! drains back to zero, and `getshieldinginfo` reports the shield txid and the value
//! arriving in the pool. A second deposit to a second address proves the loop keeps running.
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Tparty, TpartyConfig, Zebrad,
};

/// See regtest_funded.rs for the rationale behind these chain-setup constants.
const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
/// First deposit: 1 ZEC.
const DEPOSIT_ZATOSHIS: u64 = 100_000_000;
/// Second deposit: 0.5 ZEC.
const DEPOSIT2_ZATOSHIS: u64 = 50_000_000;
/// Third deposit: 0.001 ZEC - deliberately below the harness shield threshold
/// (`TpartyConfig::new` sets 0.0015) to exercise the dust-skip + `shieldfunds` path.
const DEPOSIT3_ZATOSHIS: u64 = 100_000;
/// Generous: lightwalletd ingestion + tparty scan + shielding broadcast + Orchard proving.
const SHIELD_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_tparty_deposits_auto_shield() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_tparty_deposits_auto_shield: set ZEBRAD_BIN, LIGHTWALLETD_BIN and \
             DEVTOOL_BIN to run the tparty e2e (see README.md). The harness still compiled \
             and linked."
        );
        return;
    };

    // ---- Chain + funder setup (identical to the funded zecd e2e) ----
    let funder_taddr = Funder::derive_transparent_address(&devtool_bin)
        .expect("derive funder transparent address");
    let mut zebrad = Zebrad::start_with_miner(&zebrad_bin, &funder_taddr)
        .await
        .expect("start zebrad mining to the funder");
    zebrad
        .generate_blocks(FUNDER_COINBASES)
        .await
        .expect("mine the funder's coinbases");
    zebrad
        .restart_with_miner(TAIL_MINER_ADDRESS)
        .await
        .expect("restart zebrad mining to the throwaway address");
    zebrad
        .generate_blocks(MATURITY_TAIL)
        .await
        .expect("mine the maturity tail");

    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");

    let funder = Funder::init(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(6).await.expect("confirm the funder's shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // ---- tparty against the same lightwalletd ----
    let cfg = TpartyConfig::new(lwd.grpc_port, pick_port().expect("pick tparty rpc port"));
    let tparty = Tparty::start(&cfg)
        .await
        .expect("start tparty against regtest lightwalletd");

    // Deposit addresses are fresh base58 t-addresses (regtest P2PKH = tm…).
    let addr1 = getnewaddress(&tparty).await;
    let addr2 = getnewaddress(&tparty).await;
    assert!(addr1.starts_with("tm"), "expected a tm… t-address, got {addr1}");
    assert!(addr2.starts_with("tm"), "expected a tm… t-address, got {addr2}");
    assert_ne!(addr1, addr2, "every getnewaddress call yields a fresh address");
    let v = tparty
        .call("validateaddress", json!([addr1]))
        .await
        .expect("validateaddress");
    assert_eq!(v["isvalid"], json!(true), "tparty's own address validates: {v}");

    // Nothing has been deposited: balances are zero, there is nothing to shield (the manual
    // trigger reports null), and no shield has happened.
    let info = tparty
        .call("getshieldinginfo", json!([]))
        .await
        .expect("getshieldinginfo");
    assert_eq!(info["pool"], json!("orchard"), "{info}");
    assert_eq!(info["unshielded"].as_f64(), Some(0.0), "{info}");
    assert!(info["last_shield_txid"].is_null(), "{info}");
    let manual = tparty.call("shieldfunds", json!([])).await.expect("shieldfunds");
    assert!(manual.is_null(), "nothing to shield yet: {manual}");

    // ---- Deposit 1: the funder pays the first t-address ----
    funder
        .send(lwd.grpc_port, &addr1, DEPOSIT_ZATOSHIS)
        .expect("send the transparent deposit");
    zebrad.generate_blocks(1).await.expect("confirm the deposit");

    // tparty must now, on its own: scan to the tip, discover the transparent UTXO, and
    // broadcast a shielding tx. Mine a block per poll round so the shield can confirm as
    // soon as it hits the mempool.
    let shield_txid = wait_for_shield(&zebrad, &tparty, None).await;

    // The deposit-facing story: the t-address was credited...
    let recv = tparty
        .call("getreceivedbyaddress", json!([addr1]))
        .await
        .expect("getreceivedbyaddress");
    assert_eq!(recv.as_f64(), Some(1.0), "the 1-ZEC deposit is credited to {addr1}: {recv}");
    let txs = tparty
        .call("listtransactions", json!(["*", 50]))
        .await
        .expect("listtransactions");
    assert!(
        txs.as_array().expect("array").iter().any(|t| {
            t["category"] == json!("receive") && t["address"] == json!(addr1.as_str())
        }),
        "the deposit appears as a receive on {addr1}: {txs}"
    );
    let lra = tparty
        .call("listreceivedbyaddress", json!([1, false]))
        .await
        .expect("listreceivedbyaddress");
    assert!(
        lra.as_array().expect("array").iter().any(|e| {
            e["address"] == json!(addr1.as_str())
                && e["txids"].as_array().is_some_and(|t| !t.is_empty())
        }),
        "listreceivedbyaddress lists {addr1} with its txid: {lra}"
    );

    // ...the shield is a real, mined wallet transaction...
    let gt = tparty
        .call("gettransaction", json!([shield_txid]))
        .await
        .expect("gettransaction on the shield");
    assert!(
        gt["confirmations"].as_i64().is_some_and(|c| c >= 1),
        "the shield tx confirmed: {gt}"
    );

    // ...and the unshielded balance drained into the pool: nothing transparent remains
    // (balance 0, no UTXOs), while the shielded balance grew by the deposit minus the
    // ZIP-317 fee.
    let bal = tparty.call("getbalance", json!([])).await.expect("getbalance");
    assert_eq!(bal.as_f64(), Some(0.0), "no unshielded funds remain: {bal}");
    let unspent = tparty.call("listunspent", json!([0])).await.expect("listunspent");
    assert_eq!(unspent, json!([]), "no transparent UTXOs remain");
    let info = tparty
        .call("getshieldinginfo", json!([]))
        .await
        .expect("getshieldinginfo after the shield");
    let in_pool = info["shielded"].as_f64().unwrap_or(0.0)
        + info["shielded_pending"].as_f64().unwrap_or(0.0);
    assert!(
        in_pool > 0.99,
        "the deposit (minus fee) arrived in the shielded pool: {info}"
    );
    assert_eq!(info["last_shield_txid"], json!(shield_txid.as_str()), "{info}");

    // ---- Deposit 2: the loop keeps running, on a different address ----
    funder
        .send(lwd.grpc_port, &addr2, DEPOSIT2_ZATOSHIS)
        .expect("send the second deposit");
    zebrad.generate_blocks(1).await.expect("confirm the second deposit");
    let shield2 = wait_for_shield(&zebrad, &tparty, Some(&shield_txid)).await;
    assert_ne!(shield2, shield_txid, "a fresh shield tx for the second deposit");
    let recv2 = tparty
        .call("getreceivedbyaddress", json!([addr2]))
        .await
        .expect("getreceivedbyaddress (second)");
    assert_eq!(recv2.as_f64(), Some(0.5), "the 0.5-ZEC deposit credits {addr2}: {recv2}");
    let bal = tparty.call("getbalance", json!([])).await.expect("getbalance (final)");
    assert_eq!(bal.as_f64(), Some(0.0), "everything shielded again: {bal}");

    // ---- Deposit 3: below the threshold, the auto path must NOT shield; shieldfunds must ----
    let info = tparty
        .call("getshieldinginfo", json!([]))
        .await
        .expect("getshieldinginfo (threshold)");
    assert_eq!(info["threshold"].as_f64(), Some(0.0015), "{info}");
    let addr3 = getnewaddress(&tparty).await;
    funder
        .send(lwd.grpc_port, &addr3, DEPOSIT3_ZATOSHIS)
        .expect("send the sub-threshold deposit");
    zebrad.generate_blocks(1).await.expect("confirm the dust deposit");

    // Wait until tparty has seen and confirmed the deposit (the auto-shield check runs in
    // the same caught-up pass that makes the balance visible)...
    let deadline = Instant::now() + SHIELD_TIMEOUT;
    loop {
        let bal = tparty
            .call("getbalance", json!([]))
            .await
            .expect("getbalance while waiting for the dust deposit");
        if bal.as_f64() == Some(0.001) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "tparty never saw the sub-threshold deposit: {bal}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // ...then hold for several sync intervals (2s each) and confirm it stayed unshielded.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let bal = tparty.call("getbalance", json!([])).await.expect("getbalance (held)");
    assert_eq!(
        bal.as_f64(),
        Some(0.001),
        "a sub-threshold deposit must not auto-shield: {bal}"
    );
    let info = tparty
        .call("getshieldinginfo", json!([]))
        .await
        .expect("getshieldinginfo (held)");
    assert_eq!(
        info["last_shield_txid"],
        json!(shield2.as_str()),
        "no new shield was created for the dust: {info}"
    );

    // The manual flush ignores the threshold.
    let txid3 = tparty
        .call("shieldfunds", json!([]))
        .await
        .expect("shieldfunds flushes the dust");
    let txid3 = txid3.as_str().expect("shieldfunds returns a txid").to_string();
    assert_ne!(txid3, shield2);
    let deadline = Instant::now() + SHIELD_TIMEOUT;
    loop {
        let gt = tparty
            .call("gettransaction", json!([txid3]))
            .await
            .expect("gettransaction on the manual shield");
        if gt["confirmations"].as_i64().unwrap_or(0) >= 1 {
            break;
        }
        assert!(Instant::now() < deadline, "the manual shield did not confirm: {gt}");
        zebrad.generate_blocks(1).await.expect("mine the manual shield");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let bal = tparty.call("getbalance", json!([])).await.expect("getbalance (flushed)");
    assert_eq!(bal.as_f64(), Some(0.0), "shieldfunds drained the dust: {bal}");
}

async fn getnewaddress(tparty: &Tparty) -> String {
    tparty
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("address string")
        .to_string()
}

/// Wait until `getshieldinginfo.last_shield_txid` reports a (new) shield transaction and
/// that transaction has confirmed. Mines a block each round: the deposit-confirmation,
/// shield-broadcast, and shield-confirmation steps all need block production to advance.
async fn wait_for_shield(zebrad: &Zebrad, tparty: &Tparty, previous: Option<&str>) -> String {
    let deadline = Instant::now() + SHIELD_TIMEOUT;
    loop {
        let info = tparty
            .call("getshieldinginfo", json!([]))
            .await
            .expect("getshieldinginfo while waiting for the auto-shield");
        if let Some(txid) = info["last_shield_txid"].as_str() {
            if previous != Some(txid) {
                let gt = tparty
                    .call("gettransaction", json!([txid]))
                    .await
                    .expect("gettransaction while confirming the shield");
                if gt["confirmations"].as_i64().unwrap_or(0) >= 1 {
                    return txid.to_string();
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "tparty did not auto-shield within {SHIELD_TIMEOUT:?}: {info}"
        );
        zebrad.generate_blocks(1).await.expect("mine while waiting");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
