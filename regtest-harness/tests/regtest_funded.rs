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
}
