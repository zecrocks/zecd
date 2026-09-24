//! Spending a **legacy Orchard** note after NU6.3.
//!
//! NU6.3 moves the Orchard pool to protocol V3, whose bundles must disable cross-address transfers
//! (consensus-mandated), and only the post-NU6.3 circuit constrains that flag. Orchard-pool (V2)
//! notes outlive activation - notes received before it, and change that software keeping change
//! in the Orchard pool still creates in v6 transactions after it - and spending one builds a V3
//! Orchard bundle that must be proved with the `PostNu6_3` key. zecd's PCZT send path proved it
//! with the `FixedPostNu6_2` key, which the prover refuses (`Orchard proof generation failed:
//! Prover(ProofFailed(InvalidInstances))`), so no such note could be spent.
//!
//! Nothing else in the tier can reach this: the chain activates NU6.3 at height 8, before any
//! coinbase matures, so every funded wallet elsewhere only ever holds ironwood notes. Here NU6.3
//! activates at [`NU6_3_HEIGHT`], after the funder has shielded and paid zecd, so zecd's note is a
//! legacy Orchard one; the chain then crosses activation and zecd pays a *different* wallet (the
//! funder), the shape of the failing mainnet send.
//!
//! Its own binary because it sets `ZECD_REGTEST_NU63_HEIGHT` for the whole process: zecd and the
//! funder inherit it, and it must match the node's height.
use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    attach_backend, pick_port, resolve_node_bin, start_funded_chain_live_at, RegtestNode, Zecd,
    ZecdConfig,
};

/// NU6.3 activation for this chain: past the funded bring-up (~block 140) and zecd's funding, so
/// both happen under NU6.2 and leave Orchard-pool notes.
const NU6_3_HEIGHT: u32 = 200;
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
/// Generous: chain scan + Orchard proving.
const TIMEOUT: Duration = Duration::from_secs(300);

async fn tip(zebrad: &zecd_regtest_harness::Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("tip height")
}

#[tokio::test]
async fn regtest_legacy_orchard_note_spends_after_nu6_3() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP: set {} to run the legacy-Orchard spend e2e (see README.md). \
             The harness still compiled.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };
    // Before anything spawns: zecd and the funder read it at startup.
    std::env::set_var("ZECD_REGTEST_NU63_HEIGHT", NU6_3_HEIGHT.to_string());

    let (zebrad, funder) = start_funded_chain_live_at(&zebrad_bin, NU6_3_HEIGHT)
        .await
        .expect("bring up a funded chain that activates NU6.3 late");
    assert!(
        tip(&zebrad).await < u64::from(NU6_3_HEIGHT),
        "the funded bring-up must finish before NU6.3 activates"
    );

    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let _zecd_lwd = attach_backend(&mut cfg, zebrad.rpc_port)
        .await
        .expect("attach zecd backend");
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();

    // Fund zecd under NU6.2: the payment is a legacy Orchard note.
    funder
        .send(&zecd_ua, FUND_ZATOSHIS)
        .await
        .expect("fund zecd before NU6.3");
    zebrad.generate_blocks(6).await.expect("confirm funding");
    assert!(
        tip(&zebrad).await < u64::from(NU6_3_HEIGHT),
        "zecd must be funded before NU6.3 activates"
    );

    // Cross activation, with room for the note to be spendable afterwards.
    let now = tip(&zebrad).await;
    zebrad
        .generate_blocks(u32::try_from(u64::from(NU6_3_HEIGHT) + 10 - now).expect("block count"))
        .await
        .expect("mine past NU6.3 activation");
    let height = tip(&zebrad).await;
    assert!(height > u64::from(NU6_3_HEIGHT), "NU6.3 is active");
    zecd.wait_until_synced(height, TIMEOUT)
        .await
        .expect("zecd at tip after activation");

    // Pin the input pool: the only spendable value is the legacy Orchard note.
    let unspent = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent before send");
    let unspent = unspent.as_array().expect("listunspent array");
    assert!(!unspent.is_empty(), "zecd holds its funding note");
    assert!(
        unspent.iter().all(|u| u["pool"] == "orchard"),
        "every spendable input is a legacy Orchard note, so the send must prove a V3 Orchard \
         bundle: {unspent:?}"
    );

    // Pay a different wallet. Retry only while the note is not yet selectable (-6); any other
    // error, the proving failure above above all, fails at once with its message.
    let payee = funder.unified_address().to_string();
    let deadline = Instant::now() + TIMEOUT;
    let send_txid = loop {
        match zecd.call("sendtoaddress", json!([payee, 0.3])).await {
            Ok(txid) => break txid.as_str().expect("txid string").to_string(),
            Err(e) => {
                assert!(
                    e.code() == Some(-6) && Instant::now() < deadline,
                    "spending a legacy Orchard note after NU6.3 failed: {e}"
                );
                zebrad.generate_blocks(2).await.expect("advance chain");
                let _ = zecd.wait_until_synced(tip(&zebrad).await, TIMEOUT).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    assert_eq!(send_txid.len(), 64, "a display-hex txid: {send_txid}");

    // It must be accepted and mined, not just built: the V3 Orchard bundle has to verify on the
    // node too, which is what proves the key and the cross-address routing were right.
    zebrad.generate_blocks(6).await.expect("confirm the send");
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let tx = zebrad
            .rpc("getrawtransaction", json!([send_txid, 1]))
            .await
            .expect("getrawtransaction");
        if tx["confirmations"].as_u64().unwrap_or(0) > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the legacy-Orchard send was never mined: {tx}"
        );
        zebrad.generate_blocks(1).await.expect("advance chain");
    }
}
