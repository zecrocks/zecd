//! Shielding (t->z) coin-control regtest end-to-end: prove that `z_sendmany`'s `fromaddress` is a
//! real input-side selector. A wallet-owned t-address as `fromaddress` funds the send from that
//! address's transparent UTXOs (and only that address's - coin control), `ANY_TADDR` funds it
//! from any of the wallet's transparent UTXOs, and a shielded recipient makes it the t->z
//! *shielding* send with the change shielded. All of it gated behind the `AllowRevealedSenders`
//! privacy rung: the default policy (`AllowRevealedRecipients`) must refuse to spend transparent
//! inputs, which is why this daemon deliberately runs without a `[spend] privacy_policy` line.
//!
//! Flow: bring up the funder (mine + mature + shield), fund two zecd t-addresses A (1 ZEC) and
//! B (0.3 ZEC), then:
//!  - refusals: a transparent source without the rung is a synchronous `-4` (config default and
//!    per-call `AllowRevealedAmounts` alike); a transparent source *plus* a transparent
//!    recipient under `AllowRevealedSenders` is `-4` too (fully transparent transactions keep
//!    needing `AllowFullyTransparent`); a foreign t-addr `fromaddress` stays `-5`.
//!  - coin control: shield 0.5 ZEC from A to the wallet's own UA under `AllowRevealedSenders`;
//!    B's UTXO must survive untouched (only A was selected) and the change must shield (the
//!    only remaining transparent UTXO is B's).
//!  - `ANY_TADDR`: shield 0.2 ZEC more, funded from B (the only transparent UTXO left); after
//!    it mines the wallet holds no transparent UTXOs at all.
//!  - deshield round-trip: pay the funder's t-address from the own UA under the *default*
//!    policy (a shielded/unified `fromaddress` keeps meaning shielded notes).
//!
//! Skips cleanly unless `ZEBRAD_BIN` is set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    attach_backend, pick_port, resolve_node_bin, start_funded_chain, RegtestNode, Zecd, ZecdConfig,
};

const FUND_A_ZATOSHIS: u64 = 100_000_000; // 1 ZEC
const FUND_B_ZATOSHIS: u64 = 30_000_000; // 0.3 ZEC
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
const SPEND_TIMEOUT: Duration = Duration::from_secs(240);
const OP_TIMEOUT: Duration = Duration::from_secs(120);

/// Submit a `z_sendmany` shielding send and drive it to success, retrying on `-6` while mining
/// toward spendable depth (a failed attempt builds and broadcasts nothing, so retrying is safe).
/// The send is submitted with `minconf 1` and the `AllowRevealedSenders` policy; `from` is the
/// coin-control source (a wallet t-address or `ANY_TADDR`). Returns the txid.
async fn shield_send(
    zecd: &Zecd,
    zebrad: &zecd_regtest_harness::Zebrad,
    from: &str,
    to: &str,
    amount: f64,
) -> String {
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
            .expect("zecd scans to the chain tip before shielding");
        let opid = zecd
            .call(
                "z_sendmany",
                json!([
                    from,
                    [{ "address": to, "amount": amount }],
                    1,
                    null,
                    "AllowRevealedSenders"
                ]),
            )
            .await
            .expect(
                "z_sendmany with a transparent source returns an opid under \
                     AllowRevealedSenders",
            )
            .as_str()
            .expect("opid string")
            .to_string();
        assert!(opid.starts_with("opid-"), "opid shape: {opid}");
        let waited = zecd
            .call(
                "z_waitforoperation",
                json!([opid, OP_TIMEOUT.as_secs() as i64]),
            )
            .await
            .expect("z_waitforoperation");
        assert_eq!(
            waited["finished"], true,
            "waiting on {opid} timed out rather than observing it finish: {waited}"
        );
        if waited["status"] == "success" {
            let txid = waited["result"]["txid"]
                .as_str()
                .expect("op result txid")
                .to_string();
            assert_eq!(txid.len(), 64, "z_sendmany yields a txid: {txid}");
            return txid;
        }
        let code = waited["error"]["code"].as_i64().unwrap_or(0);
        assert_eq!(
            code, -6,
            "only -6 (not yet spendable) is retryable, got: {waited}"
        );
        assert!(
            Instant::now() < deadline,
            "the transparent UTXO never became spendable in time: {waited}"
        );
        zebrad
            .generate_blocks(1)
            .await
            .expect("mine a block toward spendable depth");
    }
}

#[tokio::test]
async fn regtest_shielding_via_z_sendmany_fromaddress() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_shielding_via_z_sendmany_fromaddress: set {} to run the shielding e2e \
             (see README.md). The harness still compiled.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // 1. Bring up the chain and its funding wallet (mine + mature + shield), as in the other
    //    transparent suites.
    let (zebrad, funder) = start_funded_chain(&zebrad_bin)
        .await
        .expect("bring up a funded regtest chain");
    let funder_taddr = funder.transparent_address().to_string();

    // 2. zecd with transparent receiving enabled and NO `[spend] privacy_policy` line: the
    //    default (`AllowRevealedRecipients`) must be unable to spend transparent inputs, so the
    //    happy paths below all opt in per call via `privacyPolicy`.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.transparent = true;
    let _zecd_lwd = attach_backend(&mut cfg, zebrad.rpc_port)
        .await
        .expect("attach zecd backend");
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with transparent receiving");

    // Two external t-addresses (A and B) and the wallet's own shielded UA.
    let taddr_a = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent A")
        .as_str()
        .expect("address string")
        .to_string();
    let taddr_b = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent B")
        .as_str()
        .expect("address string")
        .to_string();
    let own_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress shielded UA")
        .as_str()
        .expect("address string")
        .to_string();
    assert!(taddr_a.starts_with("tm") && taddr_b.starts_with("tm"));
    assert!(
        !own_ua.starts_with("tm"),
        "the default address is shielded: {own_ua}"
    );

    // 3. Wait until zecd is caught up, then fund A (1 ZEC) and B (0.3 ZEC) and confirm.
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
    // Fund A, confirm it, and let the funder's shielded change reconfirm before funding B: two
    // back-to-back funder sends exhaust its spendable notes (the change from the first is
    // unconfirmed until it mines), failing the second with -6 - the documented
    // shielded-change-is-unconfirmed gotcha, and how every multi-payment suite sequences the
    // funder (see regtest_sapling).
    funder
        .send(&taddr_a, FUND_A_ZATOSHIS)
        .await
        .expect("fund zecd t-address A");
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the A funding");
    funder
        .sync(&zebrad)
        .await
        .expect("funder sync after funding A");
    funder
        .send(&taddr_b, FUND_B_ZATOSHIS)
        .await
        .expect("fund zecd t-address B");
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the B funding");
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= 1.3 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd did not reach the 1.3-ZEC transparent balance within {FUND_TIMEOUT:?} (got {bal})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 4. Refusals, all synchronous (nothing is spawned, no retry loops needed).
    //
    // 4a. A transparent source under the config default (AllowRevealedRecipients) is -4: the
    //     default must never spend transparent inputs.
    let err = zecd
        .call(
            "z_sendmany",
            json!([taddr_a, [{ "address": own_ua, "amount": 0.5 }]]),
        )
        .await
        .expect_err("a transparent fromaddress needs AllowRevealedSenders");
    assert_eq!(err.code(), Some(-4), "default policy -> -4: {err}");
    assert!(
        format!("{err}").contains("Insufficient privacy policy"),
        "the -4 names the gate: {err}"
    );
    // 4b. Same for an explicit weaker per-call policy.
    let err = zecd
        .call(
            "z_sendmany",
            json!([taddr_a, [{ "address": own_ua, "amount": 0.5 }], 1, null, "AllowRevealedAmounts"]),
        )
        .await
        .expect_err("AllowRevealedAmounts does not permit a transparent source");
    assert_eq!(err.code(), Some(-4), "AllowRevealedAmounts -> -4: {err}");
    // 4c. Transparent source + transparent recipient is a *fully transparent* transaction:
    //     AllowRevealedSenders is not enough (zcashd's split), it needs AllowFullyTransparent.
    let err = zecd
        .call(
            "z_sendmany",
            json!([taddr_a, [{ "address": funder_taddr, "amount": 0.5 }], 1, null, "AllowRevealedSenders"]),
        )
        .await
        .expect_err("a fully transparent tx needs AllowFullyTransparent");
    assert_eq!(err.code(), Some(-4), "t->t under senders-only -> -4: {err}");
    // 4d. A foreign t-address as fromaddress stays -5 (ownership is validated first).
    let err = zecd
        .call(
            "z_sendmany",
            json!([funder_taddr, [{ "address": own_ua, "amount": 0.5 }], 1, null, "AllowRevealedSenders"]),
        )
        .await
        .expect_err("a foreign fromaddress is rejected");
    assert_eq!(err.code(), Some(-5), "foreign fromaddress -> -5: {err}");

    // 5. THE COIN-CONTROLLED SHIELD: 0.5 ZEC from A to the wallet's own UA. Only A's UTXO may
    //    fund it; the change (~0.5 minus the fee) must shield.
    let txid = shield_send(&zecd, &zebrad, &taddr_a, &own_ua, 0.5).await;
    // Mine past the UNTRUSTED depth (ZIP-315 default 10), not just 1 conf: the 0.5 payment lands
    // on the wallet's own *external* UA, which the confirmations policy treats as a third-party
    // receive - only the internal change is trusted at 3 - so `getbalance` under the default
    // policy excludes it until 10 confirmations (measured: 0.7997 = B + change, payment missing).
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the shielding send");
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
            .expect("zecd syncs the shielding send");
        let confs = zecd
            .call("gettransaction", json!([txid]))
            .await
            .ok()
            .and_then(|t| t["confirmations"].as_i64())
            .unwrap_or(0);
        if confs >= 1 {
            break;
        }
        assert!(Instant::now() < deadline, "the shield never confirmed");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 5b. Coin control held: B's UTXO survived untouched, A's is gone, and everything else the
    //     wallet holds is shielded (the payment and the change both landed in the shielded
    //     pool - no transparent change appeared).
    let lu = zecd
        .call("listunspent", json!([1]))
        .await
        .expect("listunspent");
    let entries = lu.as_array().expect("listunspent array");
    let transparent: Vec<_> = entries
        .iter()
        .filter(|n| n["address"].as_str().unwrap_or("").starts_with("tm"))
        .collect();
    assert_eq!(
        transparent.len(),
        1,
        "exactly one transparent UTXO remains (B's - only A was selected): {lu}"
    );
    assert_eq!(
        transparent[0]["address"].as_str(),
        Some(taddr_b.as_str()),
        "the survivor is B's UTXO: {lu}"
    );
    assert!(
        (transparent[0]["amount"].as_f64().unwrap_or(0.0) - 0.3).abs() < 1e-8,
        "B's UTXO is untouched: {lu}"
    );
    for n in entries {
        let addr = n["address"].as_str().unwrap_or("");
        if !addr.starts_with("tm") {
            let pool = n["pool"].as_str().unwrap_or("");
            assert!(
                pool == "orchard" || pool == "ironwood",
                "shielded outputs (payment + change) land in the Orchard-family pool, got \
                 {pool:?}: {n}"
            );
        }
    }
    let bal = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("balance number");
    assert!(
        (1.29..1.301).contains(&bal),
        "nothing left the wallet but the fee (payment + change are its own): {bal}"
    );

    // 6. ANY_TADDR: shield 0.2 ZEC more. B's UTXO is the only transparent one left, so this
    //    proves the wildcard source; afterwards the wallet holds no transparent UTXOs at all.
    let txid2 = shield_send(&zecd, &zebrad, "ANY_TADDR", &own_ua, 0.2).await;
    // Past the untrusted depth again - the 0.2 payment is an own-external receive like above.
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the ANY_TADDR shield");
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
            .expect("zecd syncs the ANY_TADDR shield");
        let confs = zecd
            .call("gettransaction", json!([txid2]))
            .await
            .ok()
            .and_then(|t| t["confirmations"].as_i64())
            .unwrap_or(0);
        if confs >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the ANY_TADDR shield never confirmed"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let lu = zecd
        .call("listunspent", json!([1]))
        .await
        .expect("listunspent after ANY_TADDR");
    assert!(
        lu.as_array()
            .expect("listunspent array")
            .iter()
            .all(|n| !n["address"].as_str().unwrap_or("").starts_with("tm")),
        "every transparent UTXO is now shielded: {lu}"
    );
    let bal = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("balance number");
    assert!(
        (1.28..1.301).contains(&bal),
        "two shields cost only their fees: {bal}"
    );

    // 7. Deshield round-trip: a shielded/unified fromaddress keeps meaning shielded notes, and
    //    paying a transparent recipient from them works under the *default* policy (no
    //    privacyPolicy argument). This is the z->t direction of the same coin control.
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
            .expect("zecd scans before the deshield");
        let opid = zecd
            .call(
                "z_sendmany",
                json!([own_ua, [{ "address": funder_taddr, "amount": 0.1 }], 1]),
            )
            .await
            .expect("z_sendmany from the own UA under the default policy")
            .as_str()
            .expect("opid string")
            .to_string();
        let waited = zecd
            .call(
                "z_waitforoperation",
                json!([opid, OP_TIMEOUT.as_secs() as i64]),
            )
            .await
            .expect("z_waitforoperation for the deshield");
        assert_eq!(
            waited["finished"], true,
            "waiting on the deshield timed out: {waited}"
        );
        if waited["status"] == "success" {
            break;
        }
        let code = waited["error"]["code"].as_i64().unwrap_or(0);
        assert_eq!(code, -6, "only -6 is retryable for the deshield: {waited}");
        assert!(
            Instant::now() < deadline,
            "the shielded notes never became spendable in time: {waited}"
        );
        zebrad
            .generate_blocks(1)
            .await
            .expect("mine a block toward spendable depth");
    }
    zebrad
        .generate_blocks(3)
        .await
        .expect("confirm the deshield");
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
            .expect("zecd syncs the deshield");
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(f64::MAX);
        if bal < 1.21 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the deshield never reflected in the balance: {bal}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let bal = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("balance number");
    assert!(
        (1.18..1.21).contains(&bal),
        "0.1 ZEC left the wallet (plus fees): {bal}"
    );

    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}
