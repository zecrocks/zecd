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
//! README.md).
//!
//! Phase 1: funded receive (funder → zecd, balance + history). Phase 2: zecd *spends* - the
//! walletlock/-13/walletpassphrase gate, a real `sendtoaddress` back to the funder with
//! `gettransaction` shape checks through confirmation, and the payment-poller methods
//! (`listsinceblock` cursor loop, `getreceivedbyaddress`/`listreceivedbyaddress`), then a
//! concurrent-send burst proving the no-double-spend invariant (exactly one winner, losers
//! get -6). Finally `scripts/conformance.py` runs against the live funded daemon, putting its
//! full Bitcoin-Core wire-format suite under CI.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// Coinbase blocks mined to the funder up front. zebra finalizes blocks deeper than
/// `MAX_BLOCK_REORG_HEIGHT` (= coinbase maturity − 1 = 99) below the tip; only finalized blocks are
/// persisted to disk and survive the miner-swap restart below. So mining 120 finalizes the
/// funder's coinbases at heights ~1..21 (the rest are non-finalized and dropped on restart). This
/// matters because the light-client coinbase-maturity filter can't recognise coinbase-ness for
/// outputs discovered via lightwalletd's GetAddressUtxos (no tx_index), so the funder must simply
/// never hold an immature coinbase - the restart drops the immature (non-finalized) tail.
const FUNDER_COINBASES: u32 = 120;
/// After restarting mining to a throwaway address, mine this many blocks. The restart resets the
/// tip to the finalized height (~21); this tail re-grows the chain so the surviving funder
/// coinbases (~1..21) are well past the 100-block maturity, and gives the funder a recent tip to
/// build its shield against. Comfortably exceeds coinbase maturity (100).
const MATURITY_TAIL: u32 = 130;
/// A throwaway P2SH address that mines the maturity tail (the funder does not control it).
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
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

    // 2. Single chain: zebra first mines a few coinbases straight to the funder, then restarts
    //    mining to a throwaway address. This keeps everything on one chain while letting the
    //    funder's coinbases age past maturity without it accruing new, immature ones.
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

    // 3. lightwalletd in front of zebra (ingests the whole chain).
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");

    // 4. Initialise the funder against THIS chain, then shield its now-mature transparent coinbases
    //    into Orchard. Every coinbase the funder holds is older than the maturity tail, so the
    //    broadcast is accepted.
    let funder = Funder::init(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    // The shielded note must reach the default confirmation depth (3 for trusted/self-shielded
    // notes) before the funder can spend it; a few extra blocks cover the tip skew.
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 5. zecd against the same lightwalletd; get its Orchard unified address.
    let cfg = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
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

    // 6. Fund zecd: send Orchard funds from the funder to zecd's UA, then confirm. zecd's
    //    getbalance uses the default confirmations policy, under which an externally-received
    //    (untrusted) note needs 10 confirmations before it counts; mine a couple extra for the
    //    tip skew.
    funder
        .send(lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS)
        .expect("send Orchard funds to zecd");
    zebrad
        .generate_blocks(12)
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

    // ---- Phase 2: zecd spends ----

    // The poller methods credit the funded receive. getreceivedbyaddress: exactly the 1 ZEC
    // sent to our UA; listreceivedbyaddress lists the UA with the contributing txid.
    let recv = zecd
        .call("getreceivedbyaddress", json!([zecd_ua]))
        .await
        .expect("getreceivedbyaddress");
    assert_eq!(
        recv.as_f64(),
        Some(1.0),
        "the 1-ZEC funding receive is credited to the UA, got {recv}"
    );
    let lra = zecd
        .call("listreceivedbyaddress", json!([1, false]))
        .await
        .expect("listreceivedbyaddress");
    assert!(
        lra.as_array().expect("array").iter().any(|e| {
            e["address"] == json!(zecd_ua.as_str())
                && e["txids"].as_array().is_some_and(|t| !t.is_empty())
        }),
        "listreceivedbyaddress lists the funded UA with its txid: {lra}"
    );

    // Capture the listsinceblock cursor before the send, exactly as a payment poller would.
    let lsb = zecd
        .call("listsinceblock", json!([]))
        .await
        .expect("listsinceblock");
    let cursor = lsb["lastblock"].as_str().expect("lastblock hash").to_string();
    assert_eq!(cursor.len(), 64, "lastblock is a block hash: {lsb}");

    // The walletpassphrase gate around a real spend: locked → -13, unlocked → it goes through.
    let funder_ua = funder.unified_address().expect("funder unified address");
    zecd.call("walletlock", json!([])).await.expect("walletlock");
    let err = zecd
        .call("sendtoaddress", json!([funder_ua, 0.4]))
        .await
        .expect_err("a locked wallet must refuse to send");
    assert_eq!(err.code(), Some(-13), "expected unlock-needed (-13): {err}");
    zecd.call("walletpassphrase", json!(["any", 600]))
        .await
        .expect("walletpassphrase re-unlocks from the age identity");

    // The send-success path: a real Orchard spend back to the funder.
    let txid = zecd
        .call("sendtoaddress", json!([funder_ua, 0.4]))
        .await
        .expect("sendtoaddress succeeds with spendable funds");
    let txid = txid.as_str().expect("txid is a string").to_string();
    assert_eq!(txid.len(), 64, "txid is display hex");

    // gettransaction immediately: unconfirmed send shape (amount excludes the fee).
    let gt = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction on our own send");
    assert_eq!(
        gt["amount"].as_f64(),
        Some(-0.4),
        "gettransaction.amount is the negated payment, fee excluded: {gt}"
    );
    assert!(
        gt["fee"].as_f64().is_some_and(|f| f < 0.0),
        "fee is present and negative: {gt}"
    );
    assert_eq!(gt["confirmations"].as_i64(), Some(0), "not yet mined: {gt}");
    assert!(
        gt["hex"].as_str().is_some_and(|h| !h.is_empty()),
        "raw hex is stored for our own send: {gt}"
    );
    assert!(
        gt["details"].as_array().expect("details").iter().any(|d| {
            d["category"] == "send" && d["address"] == json!(funder_ua.as_str())
        }),
        "details carry the send to the funder: {gt}"
    );

    // Mine it in and let zecd scan; the send confirms.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(3).await.expect("confirm the send");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("zecd scans the confirming blocks");
    let gt = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction after mining");
    assert!(
        gt["confirmations"].as_i64().is_some_and(|c| c >= 1),
        "the send is confirmed: {gt}"
    );
    assert!(gt["blockheight"].is_u64(), "mined height is reported: {gt}");

    // The poller loop closes: since the pre-send cursor, the send appears; since the fresh
    // cursor, nothing confirmed is left to report.
    let lsb = zecd
        .call("listsinceblock", json!([cursor]))
        .await
        .expect("listsinceblock since the pre-send cursor");
    assert!(
        lsb["transactions"].as_array().expect("transactions").iter().any(|t| {
            t["txid"] == json!(txid.as_str()) && t["category"] == "send"
        }),
        "the send is reported since the pre-send cursor: {lsb}"
    );
    let cursor2 = lsb["lastblock"].as_str().expect("new lastblock").to_string();
    let lsb2 = zecd
        .call("listsinceblock", json!([cursor2]))
        .await
        .expect("listsinceblock since the fresh cursor");
    assert!(
        lsb2["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .all(|t| t["confirmations"].as_i64().unwrap_or(0) < 1),
        "nothing confirmed is re-reported past the fresh cursor: {lsb2}"
    );

    // ---- concurrent-send burst: the no-double-spend invariant under contention ----
    //
    // The wallet holds ~0.6 ZEC (1.0 received − 0.4 sent − fee). Fire four concurrent
    // sendtoaddress of 0.5: two successes would need 1.0+, more than the wallet holds, so
    // *exactly one* can succeed no matter how change was split into notes - the rest must
    // serialize behind it in the wallet actor and fail with -6 (insufficient funds), never by
    // double-spending the same note. This is the CI version of the manual "busy-server demo".
    //
    // First let the 0.4-send's change confirm past the trusted-note depth (3) so the burst has
    // a spendable note to fight over.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(3).await.expect("age the change");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("zecd scans the change-aging blocks");

    let burst = json!([funder_ua, 0.5]);
    let (a, b, c, d) = tokio::join!(
        zecd.call("sendtoaddress", burst.clone()),
        zecd.call("sendtoaddress", burst.clone()),
        zecd.call("sendtoaddress", burst.clone()),
        zecd.call("sendtoaddress", burst.clone()),
    );
    let results = [a, b, c, d];
    let winners: Vec<&str> = results
        .iter()
        .filter_map(|r| r.as_ref().ok().and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent send can be funded: {results:?}"
    );
    let winner_txid = winners[0].to_string();
    assert_eq!(winner_txid.len(), 64, "winning txid is display hex");
    for r in &results {
        if let Err(e) = r {
            assert_eq!(
                e.code(),
                Some(-6),
                "every losing concurrent send fails with insufficient-funds (-6): {e}"
            );
        }
    }

    // The winner is a real transaction: it mines and confirms like any other send.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(3).await.expect("confirm the winner");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("zecd scans the winner's confirmations");
    let gt = zecd
        .call("gettransaction", json!([winner_txid]))
        .await
        .expect("gettransaction on the burst winner");
    assert!(
        gt["confirmations"].as_i64().is_some_and(|c| c >= 1),
        "the burst winner confirmed on-chain: {gt}"
    );

    // ---- conformance.py against the live, funded daemon ----
    run_conformance(cfg.rpc_port, &cfg.rpc_user, &cfg.rpc_password);
}

/// Run `scripts/conformance.py` (the python-bitcoinrpc-equivalent wire-format suite) against
/// the regtest daemon. Skips with a notice if `python3` isn't available so local runs without
/// it don't fail confusingly; CI always has it.
fn run_conformance(rpc_port: u16, user: &str, password: &str) {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness lives inside the zecd repo")
        .join("scripts/conformance.py");
    let out = std::process::Command::new("python3")
        .arg(&script)
        .args([
            "--url",
            &format!("http://127.0.0.1:{rpc_port}/"),
            "--user",
            user,
            "--password",
            password,
        ])
        .output();
    match out {
        Err(e) => eprintln!("SKIP conformance.py: python3 unavailable ({e})"),
        Ok(out) => {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            assert!(
                out.status.success(),
                "conformance.py reported failures:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
