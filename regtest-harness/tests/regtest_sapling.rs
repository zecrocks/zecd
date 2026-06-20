//! Multi-pool (Sapling + Orchard) regtest end-to-end: prove that a wallet configured with both
//! shielded pools generates Sapling-bearing addresses, holds funds in **both** pools at once, and
//! reports those funds correctly across every balance/history RPC - then spends across pools.
//!
//! Setup mirrors `regtest_funded.rs`: mine a transparent coinbase to the funder, mature it, shield
//! it, then send shielded funds to zecd. The difference is that zecd is configured with
//! `[pools] enabled = ["sapling", "orchard"]`, and we fund **two** receivers - a Sapling-only one
//! and an Orchard-only one - so the wallet ends up holding one Sapling note and one Orchard note.
//! That lets us assert that getbalance / getbalances / getwalletinfo / listunspent /
//! getreceivedbyaddress all aggregate across pools.
//!
//! The funder (zcash-devtool) spends its Orchard notes; sending to a Sapling-only receiver is an
//! ordinary cross-pool transfer (devtool's `propose_transfer` takes no privacy policy - the same
//! call zecd uses when it sends Orchard→transparent in `regtest_funded`), so the value simply
//! lands as a Sapling note.
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
const FUND_ZATOSHIS: u64 = 100_000_000; // 1 ZEC per receiver
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_sapling_and_orchard_balances() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_sapling_and_orchard_balances: set ZEBRAD_BIN, LIGHTWALLETD_BIN and \
             DEVTOOL_BIN to run the multi-pool e2e (see README.md). The harness still compiled."
        );
        return;
    };

    // 1-4. Identical funder bring-up to regtest_funded: mine + mature + shield the funder.
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

    // 5. zecd with BOTH shielded pools enabled.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.pools = Some((
        vec!["sapling".into(), "orchard".into()],
        vec!["sapling".into(), "orchard".into()],
    ));
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with sapling+orchard");

    // Address generation honours the configuration: the default UA carries both receivers, and the
    // per-call overrides yield single-pool UAs. (Deterministic - no funding needed.)
    let addr_str = |v: serde_json::Value| v.as_str().expect("address string").to_string();
    let default_ua = addr_str(
        zecd.call("getnewaddress", json!([]))
            .await
            .expect("getnewaddress"),
    );
    let dv = zecd
        .call("validateaddress", json!([default_ua]))
        .await
        .expect("validateaddress default UA");
    // `receiver_types` enumerates an address's receivers (canonical order, includes transparent).
    let has_recv = |v: &serde_json::Value, t: &str| {
        v["receiver_types"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == t))
    };
    assert!(has_recv(&dv, "orchard"), "default UA has Orchard: {dv}");
    assert!(has_recv(&dv, "sapling"), "default UA has Sapling: {dv}");

    let sapling_ua = addr_str(
        zecd.call("getnewaddress", json!(["", "sapling"]))
            .await
            .expect("getnewaddress sapling"),
    );
    let orchard_ua = addr_str(
        zecd.call("getnewaddress", json!(["", "orchard"]))
            .await
            .expect("getnewaddress orchard"),
    );
    let sv = zecd
        .call("validateaddress", json!([sapling_ua]))
        .await
        .expect("validateaddress sapling UA");
    assert!(has_recv(&sv, "sapling"), "sapling UA has Sapling: {sv}");
    assert!(!has_recv(&sv, "orchard"), "sapling-only UA: {sv}");
    let ov = zecd
        .call("validateaddress", json!([orchard_ua]))
        .await
        .expect("validateaddress orchard UA");
    assert!(has_recv(&ov, "orchard"), "orchard UA has Orchard: {ov}");
    assert!(!has_recv(&ov, "sapling"), "orchard-only UA: {ov}");

    // An unknown address type is a -5 (both pools are enabled, so this is the syntax path).
    let err = zecd
        .call("getnewaddress", json!(["", "boguspool"]))
        .await
        .expect_err("unknown address type must fail");
    assert_eq!(err.code(), Some(-5), "unknown address type -> -5: {err}");

    // z_getaddressforaccount (zcashd syntax) on a sapling+orchard wallet: the default and the
    // explicit single-/dual-pool receiver sets all derive shielded-only UAs, and re-deriving at
    // a fixed diversifier index is idempotent. (Deterministic - no funding needed.)
    let a = zecd
        .call("z_getaddressforaccount", json!([0]))
        .await
        .expect("z_getaddressforaccount");
    assert_eq!(a["account"], json!(0), "account echoed: {a}");
    let a_recv = a["receiver_types"].as_array().expect("receiver_types");
    assert!(
        a_recv.iter().any(|x| x == "sapling") && a_recv.iter().any(|x| x == "orchard"),
        "default UA receiver_types are sapling+orchard: {a}"
    );
    let av = zecd
        .call("validateaddress", json!([a["address"].as_str().unwrap()]))
        .await
        .expect("validateaddress");
    assert!(has_recv(&av, "sapling") && has_recv(&av, "orchard"), "{av}");
    // Idempotent re-derivation at the chosen diversifier index returns the identical object.
    let j = a["diversifier_index"].clone();
    let a_again = zecd
        .call("z_getaddressforaccount", json!([0, [], j]))
        .await
        .expect("z_getaddressforaccount idempotent");
    assert_eq!(a_again, a, "re-derivation at a fixed index is idempotent");
    // Explicit single-pool receiver sets.
    let s = zecd
        .call("z_getaddressforaccount", json!([0, ["sapling"]]))
        .await
        .expect("z_getaddressforaccount sapling");
    assert_eq!(s["receiver_types"], json!(["sapling"]), "{s}");
    let o = zecd
        .call("z_getaddressforaccount", json!([0, ["orchard"], 0]))
        .await
        .expect("z_getaddressforaccount orchard at index 0");
    assert_eq!(o["receiver_types"], json!(["orchard"]), "{o}");
    assert_eq!(
        o["diversifier_index"],
        json!(0),
        "explicit index 0 honored: {o}"
    );
    // Transparent is never exposed, even though the wallet enables two pools: -8.
    let err = zecd
        .call("z_getaddressforaccount", json!([0, ["p2pkh"]]))
        .await
        .expect_err("p2pkh must be rejected");
    assert_eq!(err.code(), Some(-8), "p2pkh -> -8: {err}");

    // 6. Wait until zecd is caught up (so the mempool stream is open) before funding.
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

    // Fund the ORCHARD receiver first, confirm it, and let the funder's change reconfirm so its
    // next send has spendable notes.
    funder
        .send(lwd.grpc_port, &orchard_ua, FUND_ZATOSHIS)
        .expect("send to zecd's Orchard receiver");
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm Orchard send");
    funder
        .sync(lwd.grpc_port)
        .expect("funder sync after Orchard send");

    // Fund the SAPLING-only receiver: the value can only land as a Sapling note. Observe it at
    // 0 conf via the mempool stream first, then confirm.
    funder
        .send(lwd.grpc_port, &sapling_ua, FUND_ZATOSHIS)
        .expect("send to zecd's Sapling receiver");
    {
        let deadline = Instant::now() + FUND_TIMEOUT;
        loop {
            let pending = zecd
                .call("getunconfirmedbalance", json!([]))
                .await
                .expect("getunconfirmedbalance")
                .as_f64()
                .unwrap_or(0.0);
            if pending > 0.0 {
                break;
            }
            assert!(Instant::now() < deadline, "the Sapling tx never hit 0 conf");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm Sapling send");

    // 7. Both notes confirmed: the wallet holds 2 ZEC across two pools. Assert EVERY balance RPC
    //    aggregates across Sapling + Orchard.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= 2.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd did not reach the combined 2-ZEC balance within {FUND_TIMEOUT:?} (got {bal})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // getbalance: combined spendable across both pools.
    let getbalance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(
        getbalance.as_f64(),
        Some(2.0),
        "getbalance sums both pools: {getbalance}"
    );

    // getbalances: the modern triple, trusted == combined spendable, no pending.
    let getbalances = zecd
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    assert_eq!(
        getbalances["mine"]["trusted"].as_f64(),
        Some(2.0),
        "getbalances.mine.trusted sums both pools: {getbalances}"
    );
    assert_eq!(
        getbalances["mine"]["untrusted_pending"].as_f64(),
        Some(0.0),
        "no pending after confirmation: {getbalances}"
    );

    // getwalletinfo: balance / unconfirmed_balance / immature_balance.
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(
        wi["balance"].as_f64(),
        Some(2.0),
        "getwalletinfo.balance: {wi}"
    );
    assert_eq!(
        wi["unconfirmed_balance"].as_f64(),
        Some(0.0),
        "getwalletinfo.unconfirmed_balance: {wi}"
    );

    // getunconfirmedbalance: zero once both notes are confirmed.
    let unconf = zecd
        .call("getunconfirmedbalance", json!([]))
        .await
        .expect("getunconfirmedbalance");
    assert_eq!(
        unconf.as_f64(),
        Some(0.0),
        "getunconfirmedbalance is 0: {unconf}"
    );

    // listunspent: two notes (one per pool), summing to 2 ZEC.
    let lu = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let notes = lu.as_array().expect("listunspent array");
    assert_eq!(
        notes.len(),
        2,
        "exactly two unspent notes (one per pool): {lu}"
    );
    let total: f64 = notes.iter().filter_map(|n| n["amount"].as_f64()).sum();
    assert!(
        (total - 2.0).abs() < 1e-8,
        "listunspent sums to 2 ZEC: {lu}"
    );

    // getreceivedbyaddress: each receiver credited exactly its 1 ZEC.
    let recv_sapling = zecd
        .call("getreceivedbyaddress", json!([sapling_ua]))
        .await
        .expect("getreceivedbyaddress sapling");
    assert_eq!(
        recv_sapling.as_f64(),
        Some(1.0),
        "Sapling UA credited 1 ZEC: {recv_sapling}"
    );
    let recv_orchard = zecd
        .call("getreceivedbyaddress", json!([orchard_ua]))
        .await
        .expect("getreceivedbyaddress orchard");
    assert_eq!(
        recv_orchard.as_f64(),
        Some(1.0),
        "Orchard UA credited 1 ZEC: {recv_orchard}"
    );

    // History carries both receives.
    let txs = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let receives = txs
        .as_array()
        .expect("array")
        .iter()
        .filter(|t| t["category"] == "receive")
        .count();
    assert!(receives >= 2, "both receives show in history: {txs}");

    // 8a. FullPrivacy rejects a cross-pool (turnstile) send. Paying 1.5 ZEC to a Sapling-only
    //     recipient forces Orchard inputs (the Sapling note is only 1 ZEC), so the proposal spans
    //     both pools - which reveals the crossed amount and FullPrivacy forbids. This rejection
    //     happens on the *built proposal* inside the async send, so it surfaces via the
    //     operation's error (code -8), not synchronously. The default policy permits it (8b).
    let fp_opid = zecd
        .call(
            "z_sendmany",
            json!([default_ua, [{ "address": sapling_ua, "amount": 1.5 }], null, null, "FullPrivacy"]),
        )
        .await
        .expect("z_sendmany returns an opid")
        .as_str()
        .expect("opid string")
        .to_string();
    let mut saw_full_privacy_reject = false;
    for _ in 0..120 {
        let st = zecd
            .call("z_getoperationstatus", json!([[fp_opid]]))
            .await
            .expect("z_getoperationstatus");
        let obj = st
            .as_array()
            .expect("array")
            .first()
            .expect("our op")
            .clone();
        match obj["status"].as_str().expect("status string") {
            "failed" => {
                assert_eq!(
                    obj["error"]["code"].as_i64(),
                    Some(-8),
                    "FullPrivacy cross-pool send fails with -8: {obj}"
                );
                assert!(
                    obj["error"]["message"]
                        .as_str()
                        .is_some_and(|m| m.contains("FullPrivacy")),
                    "the failure names the policy: {obj}"
                );
                saw_full_privacy_reject = true;
                break;
            }
            "success" => panic!("FullPrivacy cross-pool send must not succeed: {obj}"),
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    assert!(
        saw_full_privacy_reject,
        "the FullPrivacy cross-pool send reached the failed state"
    );

    // 8b. The same cross-pool spend under the default policy succeeds (greedy input selection
    //     draws from both pools; change lands in Orchard, the strongest enabled pool).
    let funder_ua = funder.unified_address().expect("funder unified address");
    let txid = zecd
        .call("sendtoaddress", json!([funder_ua, 1.5]))
        .await
        .expect("spend across pools");
    let txid = txid.as_str().expect("txid string").to_string();
    assert_eq!(txid.len(), 64, "sendtoaddress returns a txid: {txid}");

    zebrad.generate_blocks(3).await.expect("confirm the spend");
    wait_until_confirmed(&zecd, &txid).await;

    lwd.stop();
    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}

/// Wait until `gettransaction` reports the spend at >= 1 confirmation.
async fn wait_until_confirmed(zecd: &Zecd, txid: &str) {
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let tx = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction");
        if tx["confirmations"].as_i64().unwrap_or(0) >= 1 {
            break;
        }
        assert!(Instant::now() < deadline, "the spend never confirmed");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
