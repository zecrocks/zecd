//! Multi-pool (Sapling + Orchard) regtest end-to-end: prove that a wallet configured with both
//! shielded pools generates Sapling-bearing addresses, holds funds in **both** pools at once, and
//! reports those funds correctly across every balance/history RPC - then spends via the turnstile.
//!
//! Setup mirrors `regtest_funded.rs`: mine a transparent coinbase to the funder, mature it, shield
//! it, then send shielded funds to zecd. The difference is that zecd is configured with
//! `[pools] enabled = ["sapling", "orchard"]`, and we fund **two** receivers - a Sapling-only one
//! (1 ZEC) and an Orchard-only one (2 ZEC) - so the wallet ends up holding one Sapling note and one
//! Orchard note. That lets us assert that getbalance / getbalances / getwalletinfo / listunspent /
//! getreceivedbyaddress all aggregate across pools.
//!
//! The funder (zcash-devtool) spends its Orchard notes; sending to a Sapling-only receiver is an
//! ordinary cross-pool transfer (devtool's `propose_transfer` takes no privacy policy - the same
//! call zecd uses when it sends Orchard->transparent in `regtest_funded`), so the value simply
//! lands as a Sapling note.
//!
//! NB: past the `dw/ironwood-scan-model` "select shielded inputs from a single pool group" change,
//! a single transaction never combines Orchard inputs with Sapling inputs - selection uses one
//! group (Orchard, or Sapling+Ironwood). So a payment isn't funded by draining both pools; the
//! Orchard receiver is funded to 2 ZEC (vs Sapling's 1 ZEC) so a 1.5-ZEC payment to the Sapling
//! receiver still builds - from the Orchard group - as an Orchard->Sapling *turnstile* (phase 8).
//!
//! The final phase is the flagship **tri-pool mixed-recipient `sendmany`**: a single v5 transaction
//! that carries a transparent output AND a Sapling output AND an Orchard output simultaneously,
//! funded from the wallet's Orchard change - the exact path behind the PCZT prover proving Orchard
//! spends plus a Sapling output in one shot. The two shielded legs are self-sends so each pool's
//! receipt is verifiable via `getreceivedbyaddress` (zebra's verbose getrawtransaction doesn't
//! decode shielded bundles into JSON, so this behavioral check stands in for a structural one).
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
    // A high, fixed diversifier index (not 0): zcash_client_sqlite parks the account's default
    // address at the first index with a valid Sapling diversifier - index 0 about half the time,
    // seed-dependent - and librustzcash rejects a second UA with different receivers at an
    // already-used index (DiversifierIndexReuse -> -4). A large index can't collide with that
    // low-index default, and Orchard diversifiers are valid at every index.
    let o = zecd
        .call("z_getaddressforaccount", json!([0, ["orchard"], 1_000_000]))
        .await
        .expect("z_getaddressforaccount orchard at a fixed index");
    assert_eq!(o["receiver_types"], json!(["orchard"]), "{o}");
    assert_eq!(
        o["diversifier_index"],
        json!(1_000_000),
        "explicit diversifier index honored: {o}"
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

    // Fund the ORCHARD receiver first (with 2 ZEC), confirm it, and let the funder's change
    // reconfirm so its next send has spendable notes. Orchard is funded to *twice* the Sapling
    // amount on purpose: past the `dw/ironwood-scan-model` "single pool group" change, shielded
    // inputs are selected from one of two mutually-exclusive groups (Orchard alone, or
    // Sapling+Ironwood) - Orchard is never combined with Sapling to make up a shortfall. The
    // asymmetric funding lets a 1.5-ZEC payment to the Sapling-only receiver still build (the
    // Sapling group's 1 ZEC can't cover it, so selection falls to the 2-ZEC Orchard group,
    // producing an Orchard->Sapling *turnstile*), which is what phase 8a/8b exercise.
    funder
        .send(lwd.grpc_port, &orchard_ua, 2 * FUND_ZATOSHIS)
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

    // 7. Both notes confirmed: the wallet holds 3 ZEC across two pools (2 Orchard + 1 Sapling).
    //    Assert EVERY balance RPC aggregates across Sapling + Orchard.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= 3.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd did not reach the combined 3-ZEC balance within {FUND_TIMEOUT:?} (got {bal})"
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
        Some(3.0),
        "getbalance sums both pools: {getbalance}"
    );

    // getbalances: the modern triple, trusted == combined spendable, no pending.
    let getbalances = zecd
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    assert_eq!(
        getbalances["mine"]["trusted"].as_f64(),
        Some(3.0),
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
        Some(3.0),
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

    // listunspent: two notes (one per pool - a 2-ZEC Orchard note and a 1-ZEC Sapling note),
    // summing to 3 ZEC.
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
        (total - 3.0).abs() < 1e-8,
        "listunspent sums to 3 ZEC: {lu}"
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
        Some(2.0),
        "Orchard UA credited 2 ZEC: {recv_orchard}"
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

    // 8. Turnstile spends. Past the "single pool group" input-selection change, Orchard inputs are
    //    never combined with Sapling inputs in one transaction - so a payment isn't funded by
    //    draining both pools at once; instead selection picks one group (Orchard, preferred when the
    //    payment targets Orchard) and, when that group's pool differs from the recipient's, produces
    //    a turnstile output. Both sends below spend the 2-ZEC Orchard note. First the wallet must
    //    have *scanned* to the chain
    //    tip - note witnesses plus full confirmations - not merely observed the notes at the tip.
    //    `getbalance` reports spendability relative to the chain tip and can run ahead of the scan
    //    on a slow runner, so wait for the scan to catch up before any spend (the other funded
    //    tests do this before every send); otherwise the proposal's note selection finds the notes
    //    not-yet-spendable and fails -6 instead of reaching the privacy check / completing.
    let chain_tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount")
        .as_u64()
        .expect("tip height");
    zecd.wait_until_synced(chain_tip, FUND_TIMEOUT)
        .await
        .expect("zecd scans to the chain tip before spending");

    // 8a. FullPrivacy rejects a turnstile send. Paying 1.5 ZEC to a Sapling-only recipient can't be
    //     funded from the Sapling group (only 1 ZEC), so selection falls to the 2-ZEC Orchard group,
    //     producing an Orchard->Sapling turnstile output - which reveals the crossed amount and
    //     FullPrivacy forbids. This rejection happens on the *built proposal* inside the async send,
    //     so it surfaces via the operation's error (code -8), not synchronously. The default policy
    //     permits it (8b).
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
        "the FullPrivacy turnstile send reached the failed state"
    );

    // 8b. A 1.5-ZEC spend under the default policy succeeds, funded from the 2-ZEC Orchard group.
    //     Paying the funder's unified address (which has an Orchard receiver) keeps the payment in
    //     the Orchard pool - no turnstile - with the ~0.5-ZEC change landing back in Orchard (the
    //     strongest enabled pool), which phase 9's tri-pool send then draws on. (The default policy
    //     would also permit the turnstile 8a rejected; that permission is covered by the funded
    //     e2e's transparent-recipient sends.)
    let funder_ua = funder.unified_address().expect("funder unified address");
    let txid = zecd
        .call("sendtoaddress", json!([funder_ua, 1.5]))
        .await
        .expect("orchard-funded spend");
    let txid = txid.as_str().expect("txid string").to_string();
    assert_eq!(txid.len(), 64, "sendtoaddress returns a txid: {txid}");

    zebrad.generate_blocks(3).await.expect("confirm the spend");
    wait_until_confirmed(&zecd, &txid).await;

    // 9. TRI-POOL mixed-recipient sendmany - the flagship: a single v5 transaction that carries a
    //    transparent output AND a Sapling output AND an Orchard output at once, funded from the
    //    wallet's Orchard change. This is the exact protocol path behind "the PCZT prover proves
    //    Orchard spends (+ Sapling outputs when a recipient is Sapling) in one shot", with change
    //    routed back to Orchard. We pay three recipients in one `sendmany` under the default policy:
    //      - the funder's bare t-address          -> forces a TRANSPARENT output
    //      - zecd's own Sapling-only UA           -> forces a SAPLING output (self-receive)
    //      - zecd's own Orchard-only UA           -> forces an ORCHARD output (self-receive)
    //    The two shielded legs are self-sends so the harness can *verify each pool actually
    //    received* via `getreceivedbyaddress` (the only verifiable shielded receivers in the harness
    //    are zecd's own addresses; zebra's verbose getrawtransaction doesn't decode the shielded
    //    bundles into JSON, so this behavioral check stands in for a structural one).
    const TRI_AMOUNT: f64 = 0.05;
    // Cumulative-received baselines for the two self-receivers (received totals never decrease on
    // spend, so the earlier 1-ZEC fundings sit here); we assert each grows by exactly TRI_AMOUNT.
    let sapling_before = received_by(&zecd, &sapling_ua).await;
    let orchard_before = received_by(&zecd, &orchard_ua).await;

    // The Orchard change must be scanned-to-tip and spendable; retry on -6 while aging it.
    let tri_deadline = Instant::now() + FUND_TIMEOUT;
    let tri_txid = loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("zebra getblockcount")
            .as_u64()
            .expect("tip height");
        zecd.wait_until_synced(tip, Duration::from_secs(30))
            .await
            .expect("zecd scans to the tip before the tri-pool send");
        let mut recipients = serde_json::Map::new();
        recipients.insert(funder_taddr.clone(), json!(TRI_AMOUNT));
        recipients.insert(sapling_ua.clone(), json!(TRI_AMOUNT));
        recipients.insert(orchard_ua.clone(), json!(TRI_AMOUNT));
        match zecd.call("sendmany", json!(["", recipients])).await {
            Ok(v) => break v.as_str().expect("txid string").to_string(),
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < tri_deadline,
                    "the Orchard change never became spendable for the tri-pool send: {e}"
                );
                zebrad
                    .generate_blocks(1)
                    .await
                    .expect("mine a block toward spendable depth");
            }
            Err(e) => panic!("unexpected tri-pool sendmany error: {e}"),
        }
    };
    assert_eq!(
        tri_txid.len(),
        64,
        "tri-pool sendmany returns a txid: {tri_txid}"
    );
    zebrad
        .generate_blocks(3)
        .await
        .expect("confirm the tri-pool send");
    wait_until_confirmed(&zecd, &tri_txid).await;

    // 9a. gettransaction lists exactly three sends - one per recipient - each reduced to the single
    //     receiver actually paid in its pool (display_address per-pool reduction). The transparent
    //     leg stays a bare t-addr (reduces to itself); the Sapling leg reduces to a bare Sapling
    //     receiver; the Orchard leg reduces to a single-receiver UA (Orchard has no bare encoding).
    let tri = zecd
        .call("gettransaction", json!([tri_txid]))
        .await
        .expect("gettransaction for the tri-pool send");
    let tri_sends: Vec<_> = tri["details"]
        .as_array()
        .expect("details array")
        .iter()
        .filter(|d| d["category"] == json!("send"))
        .collect();
    assert_eq!(
        tri_sends.len(),
        3,
        "one send detail per pool (transparent + Sapling + Orchard) in a single tx: {tri}"
    );
    // The transparent leg is exactly the funder's bare t-address.
    assert!(
        tri_sends
            .iter()
            .any(|d| d["address"].as_str() == Some(funder_taddr.as_str())
                && d["amount"].as_f64() == Some(-TRI_AMOUNT)),
        "the transparent leg pays the funder's bare t-address: {tri}"
    );
    // The other two legs are shielded; identify each by validating its reduced receiver's pool.
    let mut saw_sapling_leg = false;
    let mut saw_orchard_leg = false;
    for d in &tri_sends {
        let Some(addr) = d["address"].as_str() else {
            continue;
        };
        if addr == funder_taddr {
            continue;
        }
        let v = zecd
            .call("validateaddress", json!([addr]))
            .await
            .expect("validateaddress on a reduced send receiver");
        let has = |t: &str| {
            v["receiver_types"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == t))
        };
        if has("sapling") && !has("orchard") {
            saw_sapling_leg = true;
        } else if has("orchard") && !has("sapling") {
            saw_orchard_leg = true;
        }
    }
    assert!(
        saw_sapling_leg && saw_orchard_leg,
        "the two shielded legs reduce to a Sapling-only and an Orchard-only receiver: {tri}"
    );

    // 9b. Each shielded pool ACTUALLY received its output: the self-receivers' cumulative received
    //     totals each grew by exactly the paid amount. This is the behavioral proof that the single
    //     transaction really carried a Sapling output and an Orchard output (not just a transparent
    //     one with shielded change) - change lands as Orchard and is excluded from these per-address
    //     totals.
    let sapling_after = received_by(&zecd, &sapling_ua).await;
    let orchard_after = received_by(&zecd, &orchard_ua).await;
    assert!(
        (sapling_after - sapling_before - TRI_AMOUNT).abs() < 1e-8,
        "the Sapling-only receiver gained exactly {TRI_AMOUNT} (a Sapling output landed): \
         {sapling_before} -> {sapling_after}"
    );
    assert!(
        (orchard_after - orchard_before - TRI_AMOUNT).abs() < 1e-8,
        "the Orchard-only receiver gained exactly {TRI_AMOUNT} (an Orchard output landed): \
         {orchard_before} -> {orchard_after}"
    );

    lwd.stop();
    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}

/// The cumulative ZEC `getreceivedbyaddress` reports for `addr`.
async fn received_by(zecd: &Zecd, addr: &str) -> f64 {
    zecd.call("getreceivedbyaddress", json!([addr]))
        .await
        .expect("getreceivedbyaddress")
        .as_f64()
        .expect("received number")
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
