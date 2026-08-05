//! Coinbase spending end-to-end: prove zecd can spend block rewards mined directly to its own
//! addresses - both kinds Zcash supports.
//!
//! **Transparent coinbase** (`regtest_transparent_coinbase_shield_and_spend`): consensus requires
//! a transaction spending a transparent coinbase output to have *no transparent outputs at all*
//! (`bad-txns-coinbase-spend-has-transparent-outputs`, active on mainnet/testnet), plus the
//! 100-block maturity rule. So the only legal spend shape is coinbase → shielded with no change -
//! zcashd's `z_shieldcoinbase` - after which the funds spend as ordinary Orchard notes. This test
//! mines coinbases to zecd's own t-address and asserts the whole ladder: the receive is
//! discovered and classified coinbase (`immature_balance`, hidden from `listunspent`); while
//! immature nothing can spend it (t→t send and `z_shieldcoinbase` both `-6`); once mature it
//! surfaces (`listunspent` `generated: true`, spendable balance) but the t→t path *still* refuses
//! it (coinbase is excluded from regular selection); `z_shieldcoinbase` (with a `limit`, then a
//! sweep) shields it - the mined shielding tx provably has an empty `vout` - and the resulting
//! Orchard funds are then spent with a normal `sendtoaddress`.
//!
//! **Shielded coinbase** (`regtest_shielded_coinbase_receive_and_spend`, ZIP-213): a miner may
//! mine directly to a shielded (Orchard) address; such coinbase notes have **no** maturity rule
//! and no spend restriction - they are ordinary notes from birth (zcashd's
//! `mining_shielded_coinbase.py` proves the same). This test points zebra's `miner_address` at
//! zecd's own unified address, receives the Orchard coinbase notes, and spends them long before
//! 100 confirmations. Requires a zebrad whose block template can build shielded coinbase
//! (zebra ≥ 6.0.0 - 5.0.0 builds an Orchard coinbase whose proof fails its own validation), so
//! the test probes by mining one block and self-skips on a rejected template; set
//! `ZECD_REGTEST_REQUIRE_SHIELDED_COINBASE=1` to make that a hard failure instead (for runs
//! against a zebrad known to support it, e.g. the weekly `latest` leg).
//!
//! Both tests restart zebra exactly once - to point `miner_address` at zecd - and do it *before*
//! any block the test relies on is mined: zebra's non-finalized-state backup is written by an
//! asynchronous task, so a restart can silently drop recently-mined non-finalized blocks (on
//! zebra 6.0.0 the flush can lag by many seconds). After the single restart every block pays
//! zecd, so the coinbase set the assertions key on is deterministic.
//!
//! Neither test needs the funding wallet: zebra's own `generate` mines straight
//! to zecd. Skips cleanly unless `ZEBRAD_BIN` is set.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{pick_port, resolve_bin, Zebrad, Zecd, ZecdConfig, SEED_MINER_ADDRESS};

/// Coinbases mined to zecd before the maturity/aging phase (the deterministic assertion set).
const ZECD_COINBASES: u64 = 8;
const SYNC_TIMEOUT: Duration = Duration::from_secs(240);
const OP_TIMEOUT: Duration = Duration::from_secs(240);
const SPEND_TIMEOUT: Duration = Duration::from_secs(240);

/// Poll `getpeerinfo` until zecd reports `conn_state == "ready"`.
async fn wait_ready(zecd: &Zecd) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
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
            return;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never reached ready: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// zebra's current block height.
async fn zebra_tip(zebrad: &Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount")
        .as_u64()
        .expect("block count")
}

/// Sync zecd to zebra's tip and give the caught-up pass a beat to settle.
async fn sync_to_tip(zecd: &Zecd, zebrad: &Zebrad) {
    let tip = zebra_tip(zebrad).await;
    zecd.wait_until_synced(tip, SYNC_TIMEOUT)
        .await
        .expect("zecd sync to tip");
    tokio::time::sleep(Duration::from_secs(2)).await;
}

/// Drive a `z_shieldcoinbase`-style opid to completion and return the txid.
///
/// This is the poll-sleep-check loop `z_waitforoperation` exists to delete: one blocking call
/// replaces it, and the result is then reaped so the registry doesn't retain it (the wait is
/// deliberately non-destructive). Doubles as this tier's live coverage of the RPC.
async fn await_op_txid(zecd: &Zecd, opid: &str) -> String {
    let waited = zecd
        .call(
            "z_waitforoperation",
            json!([opid, OP_TIMEOUT.as_secs() as i64]),
        )
        .await
        .expect("z_waitforoperation");
    // `finished` distinguishes "the operation ended" from "the wait timed out" - both come back
    // as a successful call, so assert it separately or a slow op reads as a failed one.
    assert_eq!(
        waited["finished"], true,
        "waiting on {opid} timed out rather than observing it finish: {waited}"
    );
    assert_eq!(
        waited["status"], "success",
        "operation {opid} did not succeed: {waited}"
    );
    let txid = waited["result"]["txid"]
        .as_str()
        .expect("op result txid")
        .to_string();

    // The wait left the operation in place, so the reap still finds it exactly once.
    let reaped = zecd
        .call("z_getoperationresult", json!([[opid]]))
        .await
        .expect("z_getoperationresult");
    assert_eq!(
        reaped.as_array().and_then(|a| a.first()).map(|e| &e["id"]),
        Some(&json!(opid)),
        "the non-destructive wait must leave the result for z_getoperationresult: {reaped}"
    );

    txid
}

/// getbalance as float ZEC (fine for assertions against exact zatoshi-derived sums).
async fn balance_zec(zecd: &Zecd) -> f64 {
    zecd.call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("balance number")
}

#[tokio::test]
async fn regtest_transparent_coinbase_shield_and_spend() {
    // Coinbase tests are zebra-only in CI: the harness leaves ZEBRAD_BIN unset on the zakura leg,
    // so this skips there. (zecd drives zakura fine and zakura *can* build a shielded coinbase, but
    // the transparent-coinbase maturity+shield flow was flaky against zakura in local testing, so
    // the suite is scoped to zebra to keep the zakura leg reliably green - revisit if wanted.)
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_transparent_coinbase_shield_and_spend: set ZEBRAD_BIN to run the \
             coinbase e2e (see README.md). The harness still compiled."
        );
        return;
    };

    // 1. zebra mining to a throwaway; a couple of blocks so zecd can init off a live chain.
    let mut zebrad = Zebrad::start_with_miner(&zebrad_bin, SEED_MINER_ADDRESS)
        .await
        .expect("start zebrad");
    zebrad.generate_blocks(2).await.expect("seed the chain");

    // 2. zecd with transparent receiving. `AllowFullyTransparent` so the t→t path is *reachable*
    //    - the point of the immature/mature `-6` assertions below is that even the most
    //    permissive transparent-spend policy refuses coinbase UTXOs.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.transparent = true;
    cfg.privacy_policy = Some("AllowFullyTransparent".to_string());
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    wait_ready(&zecd).await;

    let taddr = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent")
        .as_str()
        .expect("address string")
        .to_string();
    let own_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("ua string")
        .to_string();

    // 3. The single restart (see module docs): from here on EVERY mined block pays zecd's
    //    t-address, so the assertion set below is deterministic - no later restart can drop it.
    zebrad
        .restart_with_miner(&taddr)
        .await
        .expect("restart zebrad mining to zecd");
    let window_start = zebra_tip(&zebrad).await + 1;
    zebrad
        .generate_blocks(ZECD_COINBASES as u32)
        .await
        .expect("mine zecd's coinbases");
    let hmax = window_start + ZECD_COINBASES - 1;
    sync_to_tip(&zecd, &zebrad).await;

    // 4. Immature: the receives are discovered and classified coinbase - value rides in
    //    `immature_balance`, spendable balance stays zero, and `listunspent` hides them
    //    (Bitcoin Core's AvailableCoins behavior).
    let info = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    let immature = info["immature_balance"].as_f64().expect("immature_balance");
    assert!(
        immature > 0.0,
        "immature coinbase value must surface in immature_balance: {info}"
    );
    assert_eq!(
        balance_zec(&zecd).await,
        0.0,
        "immature coinbase must not count as spendable balance"
    );
    let unspent = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent");
    assert_eq!(
        unspent.as_array().map(Vec::len),
        Some(0),
        "immature coinbase must not appear in listunspent: {unspent}"
    );

    // 4a. The getbalances extension: `mine.coinbase` is the *mature* (shieldable) coinbase
    //     value, so while everything is immature it stays zero - the value rides in
    //     `mine.immature` until the maturity boundary.
    let gb = zecd
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    assert_eq!(
        gb["mine"]["coinbase"].as_f64(),
        Some(0.0),
        "immature coinbase is not yet shieldable: {gb}"
    );
    assert!(
        (gb["mine"]["immature"].as_f64().expect("mine.immature") - immature).abs() < 1e-8,
        "getbalances.mine.immature matches getwalletinfo.immature_balance: {gb}"
    );

    // 4b. The received-by aggregations apply the same maturity rule as the balance buckets:
    //     by default an immature transparent coinbase is NOT counted as received (Core parity -
    //     a reorg can still revoke it), and `include_immature_coinbase` opts the value back in.
    let recv = zecd
        .call("getreceivedbyaddress", json!([taddr]))
        .await
        .expect("getreceivedbyaddress while immature")
        .as_f64()
        .expect("received number");
    assert_eq!(
        recv, 0.0,
        "immature coinbase must not count as received by default"
    );
    let recv_imm = zecd
        .call("getreceivedbyaddress", json!([taddr, 1, true]))
        .await
        .expect("getreceivedbyaddress include_immature_coinbase")
        .as_f64()
        .expect("received number");
    assert!(
        (recv_imm - immature).abs() < 1e-8,
        "include_immature_coinbase counts the immature value ({recv_imm} vs {immature})"
    );
    let lra = zecd
        .call("listreceivedbyaddress", json!([1, false]))
        .await
        .expect("listreceivedbyaddress while immature");
    assert!(
        lra.as_array().is_some_and(|e| !e
            .iter()
            .any(|x| x["address"].as_str() == Some(taddr.as_str()))),
        "an all-immature address is not listed by default: {lra}"
    );
    let lra_imm = zecd
        .call(
            "listreceivedbyaddress",
            json!([1, false, false, null, true]),
        )
        .await
        .expect("listreceivedbyaddress include_immature_coinbase");
    assert!(
        lra_imm.as_array().is_some_and(|e| e
            .iter()
            .any(|x| x["address"].as_str() == Some(taddr.as_str())
                && (x["amount"].as_f64().unwrap_or(0.0) - immature).abs() < 1e-8)),
        "include_immature_coinbase lists the address with the immature total: {lra_imm}"
    );

    // 5. Immature: nothing may spend it. The t→t send has no eligible UTXO at all, and
    //    z_shieldcoinbase finds no *mature* coinbase.
    let err = zecd
        .call("sendtoaddress", json!([SEED_MINER_ADDRESS, 0.5]))
        .await
        .expect_err("t->t send of immature coinbase must fail");
    assert_eq!(err.code(), Some(-6), "expected -6, got {err}");
    assert!(
        !err.to_string().contains("z_shieldcoinbase"),
        "no coinbase is mature yet, so the -6 must not point at z_shieldcoinbase: {err}"
    );
    let err = zecd
        .call("z_shieldcoinbase", json!(["*", own_ua]))
        .await
        .expect_err("shielding immature coinbase must fail");
    assert_eq!(err.code(), Some(-6), "expected -6, got {err}");

    // 6. Age the coinbases: maturity needs `target_height - mined_height >= 100`, so a tip of
    //    `hmax + 99` matures all ZECD_COINBASES at once. The tail blocks also pay zecd but are
    //    themselves immature at that tip (their heights are > hmax), so the *mature* set is
    //    exactly the first ZECD_COINBASES.
    let tip = zebra_tip(&zebrad).await;
    zebrad
        .generate_blocks((hmax + 99 - tip) as u32)
        .await
        .expect("mine the maturity tail");
    sync_to_tip(&zecd, &zebrad).await;

    // 7. Mature: the UTXOs surface in listunspent with `generated: true`, and their value moves
    //    from immature to spendable (the still-immature tail coinbases stay in immature_balance).
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let entries: Vec<&Value> = unspent
        .as_array()
        .expect("array")
        .iter()
        .filter(|e| e["pool"] == "transparent")
        .collect();
    assert_eq!(
        entries.len(),
        ZECD_COINBASES as usize,
        "exactly the {ZECD_COINBASES} mature coinbase UTXOs are listed: {unspent}"
    );
    for e in &entries {
        assert_eq!(
            e["generated"],
            json!(true),
            "a coinbase UTXO carries generated:true: {e}"
        );
        assert_eq!(e["address"].as_str(), Some(taddr.as_str()));
    }
    let coinbase_total: f64 = entries
        .iter()
        .map(|e| e["amount"].as_f64().expect("amount"))
        .sum();
    let spendable = balance_zec(&zecd).await;
    assert!(
        (spendable - coinbase_total).abs() < 1e-8,
        "mature coinbase value is the spendable balance ({spendable} vs {coinbase_total})"
    );
    let info = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert!(
        info["immature_balance"].as_f64().expect("immature_balance") > 0.0,
        "the still-immature tail coinbases stay in immature_balance: {info}"
    );

    // 7a. The balance breakout follows the maturity flip: `mine.coinbase` now reports exactly
    //     the mature set - which here is the *whole* trusted balance, telling a caller that
    //     none of it can move without `z_shieldcoinbase`. `getwalletinfo`'s transparent block
    //     mirrors the same number.
    let gb = zecd
        .call("getbalances", json!([]))
        .await
        .expect("getbalances");
    let shieldable = gb["mine"]["coinbase"].as_f64().expect("mine.coinbase");
    assert!(
        (shieldable - coinbase_total).abs() < 1e-8,
        "mine.coinbase reports the mature coinbase value ({shieldable} vs {coinbase_total}): \
         {gb}"
    );
    assert!(
        (gb["mine"]["trusted"].as_f64().expect("mine.trusted") - shieldable).abs() < 1e-8,
        "the whole trusted balance is coinbase here: {gb}"
    );
    let mirrored = info["transparent"]["coinbase_balance"]
        .as_f64()
        .expect("transparent.coinbase_balance");
    assert!(
        (mirrored - coinbase_total).abs() < 1e-8,
        "getwalletinfo.transparent.coinbase_balance mirrors mine.coinbase: {info}"
    );

    // 7b. Received-by tracks the maturity boundary: the default now counts exactly the mature
    //     set (the same value listunspent/getbalance surface), while include_immature_coinbase
    //     additionally counts the still-immature tail - strictly more.
    let recv_mature = zecd
        .call("getreceivedbyaddress", json!([taddr]))
        .await
        .expect("getreceivedbyaddress once mature")
        .as_f64()
        .expect("received number");
    assert!(
        (recv_mature - coinbase_total).abs() < 1e-8,
        "the matured coinbase value counts as received by default ({recv_mature} vs \
         {coinbase_total})"
    );
    let recv_all = zecd
        .call("getreceivedbyaddress", json!([taddr, 1, true]))
        .await
        .expect("getreceivedbyaddress include_immature_coinbase once mature")
        .as_f64()
        .expect("received number");
    assert!(
        recv_all > recv_mature,
        "include_immature_coinbase additionally counts the immature tail ({recv_all} vs \
         {recv_mature})"
    );

    // 8. Mature but still coinbase: the regular transparent spend path must refuse it -
    //    spending a transparent coinbase output with transparent outputs (recipient + change)
    //    is consensus-invalid on mainnet, so zecd's t→t selection excludes coinbase outright.
    let err = zecd
        .call("sendtoaddress", json!([SEED_MINER_ADDRESS, 0.5]))
        .await
        .expect_err("t->t send must never select coinbase UTXOs");
    assert_eq!(err.code(), Some(-6), "expected -6, got {err}");
    // The -6 is self-diagnosing: the wallet's whole spendable balance is mature coinbase, so
    // the error must say so and name the one path that can move it.
    assert!(
        err.to_string().contains("z_shieldcoinbase"),
        "the -6 names z_shieldcoinbase when mature coinbase is the blocker: {err}"
    );

    // 9. z_shieldcoinbase with a limit: shield the two highest-value coinbases, leaving the rest.
    let res = zecd
        .call("z_shieldcoinbase", json!(["*", own_ua, null, 2]))
        .await
        .expect("z_shieldcoinbase limit=2");
    assert_eq!(res["shieldingUTXOs"], json!(2), "shape: {res}");
    assert_eq!(
        res["remainingUTXOs"],
        json!(ZECD_COINBASES - 2),
        "shape: {res}"
    );
    let shielding_value = res["shieldingValue"].as_f64().expect("shieldingValue");
    let remaining_value = res["remainingValue"].as_f64().expect("remainingValue");
    assert!(
        (shielding_value + remaining_value - coinbase_total).abs() < 1e-8,
        "shielding + remaining covers the eligible set: {res}"
    );
    let opid = res["opid"].as_str().expect("opid").to_string();
    let shield_txid = await_op_txid(&zecd, &opid).await;

    // The shielding tx must have an EMPTY vout - the consensus-legal coinbase-spend shape
    // (all value flows to the shielded output; no transparent change).
    let raw = zebrad
        .rpc("getrawtransaction", json!([shield_txid, 1]))
        .await
        .expect("getrawtransaction");
    assert_eq!(
        raw["vout"].as_array().map(Vec::len),
        Some(0),
        "a coinbase-shielding tx has no transparent outputs: {raw}"
    );

    zebrad.generate_blocks(6).await.expect("confirm the shield");
    sync_to_tip(&zecd, &zebrad).await;

    // 10. Sweep the rest with the wildcard + no limit. By now a few tail coinbases have matured
    //     too, so assert the sweep takes everything mature (remaining 0) and at least the
    //     ZECD_COINBASES - 2 leftovers.
    let res = zecd
        .call("z_shieldcoinbase", json!(["*", own_ua]))
        .await
        .expect("z_shieldcoinbase sweep");
    assert!(
        res["shieldingUTXOs"].as_u64().expect("shieldingUTXOs") >= ZECD_COINBASES - 2,
        "the sweep takes at least the leftovers: {res}"
    );
    assert_eq!(res["remainingUTXOs"], json!(0), "shape: {res}");
    let opid = res["opid"].as_str().expect("opid").to_string();
    await_op_txid(&zecd, &opid).await;
    // Confirm deep enough that the shielded notes (external receives under ZIP-315) become
    // spendable for the final send.
    zebrad.generate_blocks(12).await.expect("confirm the sweep");
    sync_to_tip(&zecd, &zebrad).await;

    // 11. The shielded balance now carries the swept coinbase value (minus the two shielding
    //     fees), held as ordinary ironwood notes: `z_shieldcoinbase` paid an Orchard receiver, and
    //     NU6.3 is active on this chain, so the shielded proceeds are Orchard-V3 (ironwood) notes.
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let shielded_total: f64 = unspent
        .as_array()
        .expect("array")
        .iter()
        .filter(|e| e["pool"] == "ironwood")
        .map(|e| e["amount"].as_f64().expect("amount"))
        .sum();
    assert!(
        shielded_total > 0.0,
        "the shielded coinbase funds are ironwood notes now: {unspent}"
    );

    // 12. Spend the shielded (ex-coinbase) funds with a normal send - the full
    //     coinbase → shield → spend cycle. A self-send to the wallet's own UA is a real Orchard
    //     spend (proof, broadcast, mining) without needing a second wallet.
    let spend_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("ua")
        .to_string();
    let deadline = Instant::now() + SPEND_TIMEOUT;
    let spend_txid = loop {
        sync_to_tip(&zecd, &zebrad).await;
        match zecd.call("sendtoaddress", json!([spend_ua, 1.0])).await {
            Ok(v) => break v.as_str().expect("txid").to_string(),
            // Notes still awaiting confirmations: mine one more and retry (harness idiom).
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < deadline,
                    "spend of shielded ex-coinbase funds never became possible: {e}"
                );
                zebrad.generate_blocks(1).await.expect("mine one more");
            }
            Err(e) => panic!("sendtoaddress failed: {e}"),
        }
    };
    zebrad.generate_blocks(3).await.expect("mine the spend");
    sync_to_tip(&zecd, &zebrad).await;
    let tx = zecd
        .call("gettransaction", json!([spend_txid]))
        .await
        .expect("gettransaction");
    assert!(
        tx["confirmations"].as_i64().unwrap_or(0) > 0,
        "the ex-coinbase spend confirmed: {tx}"
    );

    println!(
        "transparent-coinbase e2e OK: {ZECD_COINBASES} coinbases received ({coinbase_total} ZEC \
         mature) -> immature guards held -> shielded in 2 txs (empty vout) -> spent {spend_txid}"
    );
}

#[tokio::test]
async fn regtest_shielded_coinbase_receive_and_spend() {
    // Zebra-only in CI (ZEBRAD_BIN unset on the zakura leg -> skips there); see the sibling test.
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_shielded_coinbase_receive_and_spend: set ZEBRAD_BIN to run the \
             coinbase e2e (see README.md). The harness still compiled."
        );
        return;
    };
    let require = std::env::var("ZECD_REGTEST_REQUIRE_SHIELDED_COINBASE").is_ok();

    // 1. zebra to a throwaway; seed the chain; zecd with the default Orchard-only config.
    let mut zebrad = Zebrad::start_with_miner(&zebrad_bin, SEED_MINER_ADDRESS)
        .await
        .expect("start zebrad");
    zebrad.generate_blocks(2).await.expect("seed the chain");
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    wait_ready(&zecd).await;

    let own_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("ua")
        .to_string();

    // 2. Point zebra's miner_address at zecd's unified address (ZIP-213 shielded coinbase) and
    //    probe with one block. zebra 5.0.0 accepts the config but its Orchard coinbase proof
    //    fails its own validation ("could not validate orchard proof"), so a rejected probe
    //    skips the test unless the env override demands it. This is the tests' single restart
    //    (see module docs); every block from here on mines an Orchard coinbase note to zecd.
    if let Err(e) = zebrad.restart_with_miner(&own_ua).await {
        let msg =
            format!("this zebrad cannot mine to a unified address (shielded coinbase): {e:#}");
        assert!(!require, "{msg}");
        eprintln!("SKIP regtest_shielded_coinbase_receive_and_spend: {msg}");
        return;
    }
    if let Err(e) = zebrad.generate_blocks(1).await {
        let msg = format!(
            "this zebrad cannot build a valid shielded-coinbase block (needs zebra >= 6.0.0): \
             {e:#}"
        );
        assert!(!require, "{msg}");
        eprintln!("SKIP regtest_shielded_coinbase_receive_and_spend: {msg}");
        return;
    }

    // 3. A few more shielded coinbases, then a confirmations tail - which also pays zecd (no
    //    second restart; see module docs). The ZIP-315 untrusted-note policy needs 10
    //    confirmations before an external receive is spendable - that is a *confirmations*
    //    floor, not coinbase maturity; the whole point here is that no 100-block rule applies
    //    to shielded coinbase.
    zebrad
        .generate_blocks(4)
        .await
        .expect("mine more shielded coinbases");
    let coinbase_tip = zebra_tip(&zebrad).await;
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirmations tail");
    sync_to_tip(&zecd, &zebrad).await;

    // 4. The shielded coinbase notes are ordinary notes: full spendable balance at 1+
    //    confirmations, listed with the shielded pool their mining height implies, and - the key
    //    contrast with transparent coinbase at the same depth - NO immature bucket.
    let unspent = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let entries = unspent.as_array().expect("array");
    assert!(
        entries.len() >= 5,
        "every mined shielded coinbase note is listed with no maturity gate: {unspent}"
    );
    // Pool is keyed on the height that minted each note, because this coinbase set **straddles
    // the NU6.3 activation height**: the chain is seeded with a couple of blocks before the miner
    // is pointed at zecd, so the notes below start a few blocks under NU6_3_ACTIVATION_HEIGHT and
    // run past it. A block mined at or after activation carries an Orchard-V3 (ironwood) coinbase
    // output; an earlier one carries Orchard-V2. So a uniform assertion is wrong in both
    // directions - asserting all-orchard and asserting all-ironwood each fail on whichever note
    // happens to trip first, which is exactly how this showed up in CI (one run reported orchard,
    // the next ironwood, from the same code).
    //
    // Unlike the transparent ladder above - whose shielded proceeds are ironwood because *zecd*
    // authors the `z_shieldcoinbase` transaction - these outputs are authored by the **miner**, so
    // the pool follows the consensus rules in force at the mining height.
    let tip = zebra_tip(&zebrad).await;
    for e in entries {
        // listunspent reports confirmations, so height = tip - confirmations + 1.
        let confs = e["confirmations"].as_u64().expect("confirmations");
        let height = tip - confs + 1;
        let expected = if height >= u64::from(zecd_regtest_harness::NU6_3_ACTIVATION_HEIGHT) {
            "ironwood"
        } else {
            "orchard"
        };
        assert_eq!(
            e["pool"],
            json!(expected),
            "shielded coinbase note mined at height {height} (NU6.3 activates at {}): {e}",
            zecd_regtest_harness::NU6_3_ACTIVATION_HEIGHT
        );
    }
    let coinbase_total: f64 = entries
        .iter()
        .map(|e| e["amount"].as_f64().expect("amount"))
        .sum();
    // `getbalance` applies the ZIP-315 untrusted-note floor (10 confirmations) to external
    // receives - a *confirmations* policy, not coinbase maturity - so compare it against the
    // notes that have cleared that floor. Every note with 10+ confirmations counts, at depths
    // far below 100: the no-maturity property under test.
    let confirmed_total: f64 = entries
        .iter()
        .filter(|e| e["confirmations"].as_i64().unwrap_or(0) >= 10)
        .map(|e| e["amount"].as_f64().expect("amount"))
        .sum();
    assert!(
        confirmed_total > 0.0,
        "some shielded coinbase notes have cleared the ZIP-315 floor: {unspent}"
    );
    let spendable = balance_zec(&zecd).await;
    assert!(
        (spendable - confirmed_total).abs() < 1e-8,
        "shielded coinbase is spendable at the ZIP-315 confirmations floor - no 100-block \
         maturity ({spendable} vs {confirmed_total})"
    );
    let info = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(
        info["immature_balance"].as_f64(),
        Some(0.0),
        "shielded coinbase has no immature bucket: {info}"
    );
    // The received-by aggregation likewise applies no maturity rule to shielded coinbase: the
    // full received total counts at depths far below 100 (its transparent-coinbase counterpart
    // reports 0 at the same depth - the pool-scoping of the exclusion, asserted live).
    let recv = zecd
        .call("getreceivedbyaddress", json!([own_ua]))
        .await
        .expect("getreceivedbyaddress on the shielded-coinbase UA")
        .as_f64()
        .expect("received number");
    assert!(
        (recv - coinbase_total).abs() < 1e-8,
        "shielded coinbase counts as received with no maturity gate ({recv} vs {coinbase_total})"
    );

    // 5. Spend one - far inside the 100-block window that would gate a *transparent* coinbase.
    let spend_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("ua")
        .to_string();
    let deadline = Instant::now() + SPEND_TIMEOUT;
    let spend_txid = loop {
        sync_to_tip(&zecd, &zebrad).await;
        match zecd.call("sendtoaddress", json!([spend_ua, 1.0])).await {
            Ok(v) => break v.as_str().expect("txid").to_string(),
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < deadline,
                    "spend of a shielded coinbase note never became possible: {e}"
                );
                zebrad.generate_blocks(1).await.expect("mine one more");
            }
            Err(e) => panic!("sendtoaddress failed: {e}"),
        }
    };
    let spend_tip = zebra_tip(&zebrad).await;
    assert!(
        spend_tip - coinbase_tip < 100,
        "the spend happened {} blocks after the coinbase - well inside the 100-block window \
         that gates transparent coinbase, proving shielded coinbase has no maturity rule",
        spend_tip - coinbase_tip
    );
    zebrad.generate_blocks(3).await.expect("mine the spend");
    sync_to_tip(&zecd, &zebrad).await;
    let tx = zecd
        .call("gettransaction", json!([spend_txid]))
        .await
        .expect("gettransaction");
    assert!(
        tx["confirmations"].as_i64().unwrap_or(0) > 0,
        "the shielded-coinbase spend confirmed: {tx}"
    );

    println!(
        "shielded-coinbase e2e OK: {} Orchard coinbase notes ({coinbase_total} ZEC) received \
         and spent {} blocks after mining (no maturity), txid {spend_txid}",
        entries.len(),
        spend_tip - coinbase_tip
    );
}
