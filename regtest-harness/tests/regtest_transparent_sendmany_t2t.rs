//! Fully-transparent (t→t) spend via **`sendmany`** regtest end-to-end.
//!
//! This is the belt-and-suspenders counterpart to `regtest_transparent_t2t.rs`, which exercises the
//! fully-transparent spend path through `sendtoaddress`. All three send RPCs
//! (`sendtoaddress`/`sendmany`/`z_sendmany`) funnel through the same `do_send` actor path, so the
//! transparent-builder mechanism is already covered - but `sendmany` is the one send RPC whose
//! *only* route to a fully-transparent spend is the `[spend] privacy_policy = "AllowFullyTransparent"`
//! config knob (unlike `z_sendmany` it has no per-call `privacyPolicy` argument, and unlike the
//! default `AllowRevealedRecipients` it must opt in to fund from transparent UTXOs with
//! kept-transparent change). This test asserts that specific config-driven seam directly: a
//! `sendmany` paying a transparent recipient, with the policy read from config, produces a t→t spend
//! whose change stays transparent (no shielded balance appears). (The negative - that the *default*
//! `AllowRevealedRecipients` policy returns `-6` for a transparent-only wallet - is covered by
//! `regtest_transparent.rs`; here we assert the config-driven positive.)
//!
//! Flow mirrors `regtest_transparent_t2t.rs`: bring up the funder (mine + mature + shield), fund
//! zecd's t-address, then pay **two** transparent recipients in one `sendmany` for less than the
//! wallet holds (forcing change). The two outputs from one transparent input also exercise
//! `select_transparent_inputs` spanning multiple recipient outputs and the multi-output ZIP-317 fee.
//! After the send mines, every remaining UTXO is transparent change at an own `t`-address (not a
//! shielded note), the change is hidden as change in history (two sends - the two recipients - no
//! phantom self-payment), and a second `sendmany` re-spends that change.
//!
//! Skips cleanly unless `ZEBRAD_BIN` is set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_node_bin, start_funded_chain, RegtestNode, Zecd, ZecdConfig,
    SEED_MINER_ADDRESS,
};

const FUND_ZATOSHIS: u64 = 100_000_000; // 1 ZEC
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
const SPEND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_fully_transparent_sendmany_keeps_change_transparent() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_fully_transparent_sendmany_keeps_change_transparent: set {} to run the \
             fully-transparent sendmany e2e. The harness still compiled.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // 1-4. Identical funder bring-up to regtest_transparent_t2t: mine + mature + shield the funder.
    // 1-4. Bring up the chain and its funding wallet: seed blocks to a throwaway address,
    //      create the funder against them, mine and mature its coinbase, shield it into
    //      Orchard. See `start_funded_chain`.
    let (zebrad, funder) = start_funded_chain(&zebrad_bin)
        .await
        .expect("bring up a funded regtest chain");
    // The funder's own bare t-address, used here as an external transparent counterparty.
    let funder_taddr = funder.transparent_address().to_string();

    // 5. zecd with transparent receiving AND the fully-transparent spend policy. `sendmany` has no
    //    per-call privacyPolicy argument, so this config knob is its ONLY route to a t→t spend.
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
        .send(&taddr, FUND_ZATOSHIS)
        .await
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

    // 9. THE CONFIG-DRIVEN seam: a multi-output `sendmany` paying TWO transparent recipients -
    //    the funder's t-address 0.3 ZEC and a second throwaway t-address 0.2 ZEC - in one tx
    //    (forcing transparent change). Two outputs from one transparent input also exercises
    //    `select_transparent_inputs` covering multiple recipient outputs and the multi-output
    //    ZIP-317 fee. With no per-call privacyPolicy argument, the only thing that lets a `sendmany`
    //    fund from transparent UTXOs at all is `[spend] privacy_policy = "AllowFullyTransparent"` in
    //    config. The received UTXO is third-party (untrusted), so it becomes spendable only at the
    //    confirmations-policy depth; mine toward it and retry on -6 (a failed attempt builds and
    //    broadcasts nothing, so retrying is safe).
    let second_taddr = SEED_MINER_ADDRESS; // a valid regtest transparent address (t2… P2SH)
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
        let mut recipients = serde_json::Map::new();
        recipients.insert(funder_taddr.clone(), json!(0.3));
        recipients.insert(second_taddr.to_string(), json!(0.2));
        match zecd.call("sendmany", json!(["", recipients])).await {
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
            Err(e) => panic!("unexpected sendmany error: {e}"),
        }
    };
    assert_eq!(txid.len(), 64, "sendmany returns a txid: {txid}");

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
    //     funds, so any remaining balance reported with a bare `t`-address (not an empty / shielded
    //     note) proves the `sendmany` change did NOT auto-shield. Every unspent output must be
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

    // 11b. The change is HIDDEN from history (routed to the internal change chain), so the sendmany
    //      lists exactly the two external recipients - no phantom self-payment for the change.
    let gt = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction for the sendmany");
    let details = gt["details"]
        .as_array()
        .expect("gettransaction details array");
    let sends: Vec<_> = details
        .iter()
        .filter(|d| d["category"] == json!("send"))
        .collect();
    assert_eq!(
        sends.len(),
        2,
        "exactly two sends (the two recipients) - the change is hidden as change, not a phantom \
         self-payment: {gt}"
    );
    assert!(
        sends
            .iter()
            .any(|d| d["address"].as_str() == Some(funder_taddr.as_str())
                && d["amount"].as_f64() == Some(-0.3)),
        "one send is the 0.3 ZEC payment to the funder recipient: {gt}"
    );
    assert!(
        sends
            .iter()
            .any(|d| d["address"].as_str() == Some(second_taddr)
                && d["amount"].as_f64() == Some(-0.2)),
        "the other send is the 0.2 ZEC payment to the second recipient: {gt}"
    );

    // 12. Spend the change with a second `sendmany`, proving the change was recorded, rediscovered by
    //     the receive scan, and signable with the change address's key.
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
        let mut recipients = serde_json::Map::new();
        recipients.insert(funder_taddr.clone(), json!(0.1));
        match zecd.call("sendmany", json!(["", recipients])).await {
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
            Err(e) => panic!("unexpected second sendmany error: {e}"),
        }
    };
    assert_eq!(
        txid2.len(),
        64,
        "the change is spendable by a second sendmany: {txid2}"
    );
    zebrad
        .generate_blocks(3)
        .await
        .expect("confirm the change spend");
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
            .expect("zecd syncs the change spend");
        if zecd
            .call("gettransaction", json!([txid2]))
            .await
            .ok()
            .and_then(|t| t["confirmations"].as_i64())
            .unwrap_or(0)
            >= 1
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the change spend never confirmed"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}
