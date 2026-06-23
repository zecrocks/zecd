//! Fully-transparent (t→t) spend regtest end-to-end: prove that a wallet configured with `[pools]
//! transparent = true` **and** `[spend] privacy_policy = "AllowFullyTransparent"` can spend a
//! received transparent UTXO to a transparent recipient while **keeping the change transparent** -
//! a normal bitcoin-style send that never touches a shielded pool. This is the differentiator from
//! `regtest_transparent.rs` (which only receives): here we assert the change stays transparent
//! (zero shielded balance appears) and that the change UTXO is itself spendable by a second send.
//!
//! Flow: bring up the funder (mine + mature + shield) as in `regtest_transparent.rs`, fund zecd's
//! t-address, then have zecd pay the funder's t-address for less than it holds (forcing change).
//! After the send mines, the wallet's remaining balance is the transparent change at an own
//! `t`-address (not a shielded note). The change is routed to the wallet's INTERNAL change chain,
//! so `gettransaction` hides it (one send, no phantom self-payment); a second send then consumes
//! the change (proving it was recorded, rediscovered, and signable); and a final INTENTIONAL
//! self-send to the wallet's own EXTERNAL address stays visible (send+receive), proving the
//! change-hiding does not swallow deliberate self-payments.
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const FUND_ZATOSHIS: u64 = 100_000_000; // 1 ZEC
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
const SPEND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_fully_transparent_spend_keeps_change_transparent() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_fully_transparent_spend_keeps_change_transparent: set ZEBRAD_BIN, \
             LIGHTWALLETD_BIN and DEVTOOL_BIN to run the fully-transparent spend e2e (see \
             README.md). The harness still compiled."
        );
        return;
    };

    // 1-4. Identical funder bring-up to regtest_transparent: mine + mature + shield the funder.
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
        .expect("shield transparent coinbase");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 5. zecd with transparent receiving AND the fully-transparent spend policy.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.transparent = true;
    cfg.privacy_policy = Some("AllowFullyTransparent".to_string());
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with fully-transparent spending");

    let taddr = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent")
        .as_str()
        .expect("address string")
        .to_string();
    assert!(
        taddr.starts_with("tm"),
        "zecd hands out a bare t-addr (tm…), got {taddr}"
    );

    // 6. Wait until zecd is caught up before funding.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let peers = zecd
            .call("getpeerinfo", json!([]))
            .await
            .expect("getpeerinfo");
        if peers
            .as_array()
            .and_then(|a| a.first())
            .is_some_and(|p| p["conn_state"] == "ready")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never reached ready: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 7. Fund zecd's transparent address and confirm it (transparent receives are found once mined).
    funder
        .send(lwd.grpc_port, &taddr, FUND_ZATOSHIS)
        .expect("send to zecd's transparent address");
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm transparent receive");

    // 8. Wait for the 1-ZEC transparent balance.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= 1.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd did not reach the 1-ZEC transparent balance within {FUND_TIMEOUT:?} (got {bal})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 9. The fully-transparent spend: pay the funder's t-address 0.5 ZEC (forcing transparent
    //    change). The received UTXO is third-party (untrusted), so it becomes spendable only at the
    //    confirmations-policy depth; mine toward it and retry on -6 (a failed attempt builds and
    //    broadcasts nothing, so retrying is safe).
    let deadline = Instant::now() + SPEND_TIMEOUT;
    let txid = loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("zebra getblockcount")
            .as_u64()
            .expect("tip height");
        zecd.wait_until_synced(tip, Duration::from_secs(30))
            .await
            .expect("zecd scans to the chain tip before spending");
        match zecd.call("sendtoaddress", json!([funder_taddr, 0.5])).await {
            Ok(v) => break v.as_str().expect("txid string").to_string(),
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < deadline,
                    "the transparent UTXO never became spendable in time: {e}"
                );
                zebrad
                    .generate_blocks(1)
                    .await
                    .expect("mine a block toward spendable depth");
            }
            Err(e) => panic!("unexpected sendtoaddress error: {e}"),
        }
    };
    assert_eq!(txid.len(), 64, "sendtoaddress returns a txid: {txid}");

    // 10. Confirm the spend and let zecd rediscover the change.
    zebrad.generate_blocks(3).await.expect("confirm the spend");
    let deadline = Instant::now() + SPEND_TIMEOUT;
    loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("zebra getblockcount")
            .as_u64()
            .expect("tip height");
        zecd.wait_until_synced(tip, Duration::from_secs(30))
            .await
            .expect("zecd syncs the spend");
        let txn = zecd
            .call("gettransaction", json!([txid]))
            .await
            .ok()
            .and_then(|t| t["confirmations"].as_i64())
            .unwrap_or(0);
        if txn >= 1 {
            break;
        }
        assert!(Instant::now() < deadline, "the spend never confirmed");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 11. THE DIFFERENTIATOR: the change stayed transparent. The wallet only ever held transparent
    //     funds, so any remaining balance that is reported with a bare `t`-address (not an empty /
    //     shielded note) proves the change did NOT auto-shield. Every unspent output must be
    //     transparent (a `tm…` address); `getbalance` reflects ~0.5 ZEC minus the fee.
    let lu = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent");
    let notes = lu.as_array().expect("listunspent array");
    assert!(
        !notes.is_empty(),
        "the transparent change is unspent and visible: {lu}"
    );
    for n in notes {
        let addr = n["address"].as_str().unwrap_or("");
        assert!(
            addr.starts_with("tm"),
            "every remaining UTXO is transparent (kept-transparent change), got address {addr:?}: \
             {lu}"
        );
    }
    let change_balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("balance number");
    assert!(
        (0.49..0.50).contains(&change_balance),
        "the transparent change is ~0.5 ZEC minus the fee: {change_balance}"
    );

    // 11b. The change is HIDDEN from history. It is routed to the wallet's INTERNAL (change) chain,
    //      not an external receive address, so `gettransaction` lists exactly one send - the
    //      payment to the funder - with no phantom self-payment for the change. (A from-seed
    //      re-sync recovers the change via the internal gap chain and likewise recognizes it as
    //      change, so this stays true after restore.)
    let gt = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction for the send");
    let details = gt["details"]
        .as_array()
        .expect("gettransaction details array");
    let sends: Vec<_> = details
        .iter()
        .filter(|d| d["category"] == json!("send"))
        .collect();
    assert_eq!(
        sends.len(),
        1,
        "exactly one send (the recipient) - the change is hidden as change, not a phantom \
         self-payment: {gt}"
    );
    assert_eq!(
        sends[0]["address"].as_str(),
        Some(funder_taddr.as_str()),
        "the single send is to the external recipient, not the change address: {gt}"
    );

    // 12. Spend the change: a second t→t send consuming the change UTXO. This proves the change was
    //     recorded, rediscovered by the receive scan, and signable with the change address's key.
    let deadline = Instant::now() + SPEND_TIMEOUT;
    let txid2 = loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("zebra getblockcount")
            .as_u64()
            .expect("tip height");
        zecd.wait_until_synced(tip, Duration::from_secs(30))
            .await
            .expect("zecd scans before the second spend");
        match zecd.call("sendtoaddress", json!([funder_taddr, 0.1])).await {
            Ok(v) => break v.as_str().expect("txid string").to_string(),
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < deadline,
                    "the transparent change never became spendable in time: {e}"
                );
                zebrad
                    .generate_blocks(1)
                    .await
                    .expect("mine a block toward spendable depth");
            }
            Err(e) => panic!("unexpected second sendtoaddress error: {e}"),
        }
    };
    assert_eq!(
        txid2.len(),
        64,
        "the change is spendable by a second send: {txid2}"
    );
    zebrad
        .generate_blocks(3)
        .await
        .expect("confirm the change spend");

    // 13. An INTENTIONAL self-send stays VISIBLE. Paying the wallet's own *external* (receive)
    //     address is a deliberate payment, not change, so it must surface in history as a
    //     send+receive pair - proving the internal-change hiding does not swallow legitimate
    //     self-payments. (The change of *this* tx is on the internal chain and stays hidden.)
    let own_addr = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress for the self-send")
        .as_str()
        .expect("own address string")
        .to_string();
    let deadline = Instant::now() + SPEND_TIMEOUT;
    let self_txid = loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("zebra getblockcount")
            .as_u64()
            .expect("tip height");
        zecd.wait_until_synced(tip, Duration::from_secs(30))
            .await
            .expect("zecd scans before the self-send");
        match zecd.call("sendtoaddress", json!([own_addr, 0.05])).await {
            Ok(v) => break v.as_str().expect("txid string").to_string(),
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < deadline,
                    "funds never became spendable for the self-send in time: {e}"
                );
                zebrad
                    .generate_blocks(1)
                    .await
                    .expect("mine a block toward spendable depth");
            }
            Err(e) => panic!("unexpected self-send error: {e}"),
        }
    };
    zebrad
        .generate_blocks(3)
        .await
        .expect("confirm the self-send");
    let deadline = Instant::now() + SPEND_TIMEOUT;
    loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("zebra getblockcount")
            .as_u64()
            .expect("tip height");
        zecd.wait_until_synced(tip, Duration::from_secs(30))
            .await
            .expect("zecd syncs the self-send");
        if zecd
            .call("gettransaction", json!([self_txid]))
            .await
            .ok()
            .and_then(|t| t["confirmations"].as_i64())
            .unwrap_or(0)
            >= 1
        {
            break;
        }
        assert!(Instant::now() < deadline, "the self-send never confirmed");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let gt_self = zecd
        .call("gettransaction", json!([self_txid]))
        .await
        .expect("gettransaction for the self-send");
    let details_self = gt_self["details"]
        .as_array()
        .expect("self-send details array");
    assert!(
        details_self
            .iter()
            .any(|d| d["category"] == json!("send") && d["address"].as_str() == Some(&own_addr)),
        "an intentional self-send shows a send to the own address: {gt_self}"
    );
    assert!(
        details_self
            .iter()
            .any(|d| d["category"] == json!("receive") && d["address"].as_str() == Some(&own_addr)),
        "an intentional self-send shows a receive at the own address: {gt_self}"
    );

    lwd.stop();
    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}
