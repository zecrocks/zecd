//! Transparent offline-window restore: a wallet receives on a t-address and spends it, then goes
//! away; a from-seed restore that never saw either transaction live must recover the **full
//! receive+send pair**.
//!
//! This is deliberately backend-agnostic, because the offline window turned out to be testing
//! something no backend actually guarantees. Transparent *receives* ride the block scan (zebra
//! parses full blocks; a versioned-protocol lightwalletd carries transparent data in compact
//! blocks), so the receive half is covered. Transparent *spends* ride neither: the matcher only
//! inspects outputs (`engine::owned_transparent_output`), so a spend is discovered solely when
//! librustzcash asks zecd to check an address via `TransactionDataRequest::
//! TransactionsInvolvingAddress`. When zecd records a UTXO itself - which is exactly what the
//! block-scan matcher does - librustzcash was observed never to emit that spend-search, so the
//! spend is never found and the restore shows a receive with no matching send.
//!
//! The failure was measured before the fix: the restore reported a balance of 0.7999 against the
//! authoring wallet's actual 0.2999, holding 2 unspent outputs where there was 1 - the wallet
//! believing it still held money it had already spent, and able to select the spent output for a
//! send that would fail at broadcast.
//!
//! Skips cleanly unless the node binary, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set
//! (lightwalletd is needed for the devtool funder even on the zebra leg).

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, resolve_node_bin, Funder, Lightwalletd, RegtestNode, Zebrad, Zecd,
    ZecdConfig,
};

const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
/// How long the restore gets to surface the pair once it has scanned to the tip. Generous: the
/// enhancement backlog has to drain before the history is complete.
const RECOVER_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn regtest_transparent_offline_receive_and_spend_are_restored() {
    let (Some(node_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_node_bin(),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_transparent_offline_receive_and_spend_are_restored: set {}, \
             LIGHTWALLETD_BIN and DEVTOOL_BIN to run the offline-restore e2e (see README.md). \
             The harness still compiled.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // Funder bring-up, identical to the other transparent suites: mine + mature + shield.
    let funder_taddr = Funder::derive_transparent_address(&devtool_bin)
        .expect("derive funder transparent address");
    let mut zebrad = Zebrad::start_with_miner(&node_bin, &funder_taddr)
        .await
        .expect("start the node mining to the funder");
    zebrad
        .generate_blocks(FUNDER_COINBASES)
        .await
        .expect("mine the funder's coinbases");
    zebrad
        .restart_with_miner(TAIL_MINER_ADDRESS)
        .await
        .expect("restart the node mining to the throwaway address");
    zebrad
        .generate_blocks(MATURITY_TAIL)
        .await
        .expect("mine the maturity tail");
    let funder_lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start the funder's lightwalletd");
    let funder = Funder::init(&devtool_bin, funder_lwd.grpc_port).expect("initialise the funder");
    funder
        .sync(funder_lwd.grpc_port)
        .expect("funder sync (coinbase)");
    funder
        .shield(funder_lwd.grpc_port)
        .expect("shield transparent coinbase");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder
        .sync(funder_lwd.grpc_port)
        .expect("funder sync (shielded)");

    // A. The authoring wallet: transparent receiving plus fully-transparent spends, so the t→t
    //    send keeps its change transparent and never touches a shielded pool.
    let pre_fund_height = tip_height(&zebrad).await;
    let mut author_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("rpc port"));
    author_cfg.transparent = true;
    author_cfg.privacy_policy = Some("AllowFullyTransparent".to_string());
    let author = Zecd::start(&author_cfg)
        .await
        .expect("start the authoring zecd");
    let mnemonic = author
        .mnemonic
        .clone()
        .expect("a fresh init prints its mnemonic");
    let taddr = author
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent")
        .as_str()
        .expect("address string")
        .to_string();

    // Fund the t-addr and wait for the mined receive.
    funder
        .send(funder_lwd.grpc_port, &taddr, FUND_ZATOSHIS / 2)
        .expect("fund the authoring wallet's t-addr");
    zebrad
        .generate_blocks(2)
        .await
        .expect("mine the funding tx");
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let tip = tip_height(&zebrad).await;
        author
            .wait_until_synced(u64::from(tip), Duration::from_secs(30))
            .await
            .expect("author scans to the tip");
        let bal = author
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= 0.5 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the authoring wallet never saw its transparent funding (got {bal})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Spend it t→t, confirm, then stop the authoring wallet: from here on nothing is watching.
    let deadline = Instant::now() + FUND_TIMEOUT;
    let spend_txid = loop {
        match author
            .call("sendtoaddress", json!([funder_taddr, 0.2]))
            .await
        {
            Ok(v) => break v.as_str().expect("txid string").to_string(),
            Err(e) if e.code() == Some(-6) => {
                assert!(
                    Instant::now() < deadline,
                    "the transparent UTXO never became spendable: {e}"
                );
                zebrad
                    .generate_blocks(1)
                    .await
                    .expect("mine toward spendable depth");
                let tip = tip_height(&zebrad).await;
                author
                    .wait_until_synced(u64::from(tip), Duration::from_secs(30))
                    .await
                    .expect("author rescans");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("fully-transparent spend failed: {e}"),
        }
    };
    // Confirm the spend, and leave a few blocks of headroom so the restore's scan and the
    // enhancement backlog both have a settled chain to work against.
    zebrad
        .generate_blocks(4)
        .await
        .expect("confirm the authoring t-spend");
    let tip = tip_height(&zebrad).await;
    author
        .wait_until_synced(u64::from(tip), Duration::from_secs(60))
        .await
        .expect("author sees its own spend confirmed");
    // Sanity: the authoring wallet - which watched both transactions live - has the full pair.
    // If this fails the test is wrong, not zecd.
    let author_txs = author
        .call("listtransactions", json!(["*", 100]))
        .await
        .expect("listtransactions on the author");
    let author_arr = author_txs.as_array().cloned().unwrap_or_default();
    assert!(
        author_arr
            .iter()
            .any(|t| t["category"] == "receive" && t["address"] == json!(taddr)),
        "the authoring wallet should have recorded its own receive: {author_txs}"
    );
    assert!(
        author_arr
            .iter()
            .any(|t| t["category"] == "send" && t["txid"] == json!(spend_txid)),
        "the authoring wallet should have recorded its own spend: {author_txs}"
    );
    // The authoring wallet's post-spend balance is the ground truth the restore must converge on.
    // An undiscovered spend does not just lose history: the UTXO stays in the wallet's unspent
    // set, so the restore would report a *higher* balance than the wallet really has and would
    // offer an already-spent output for selection. Capture it so the failure message says which.
    let author_balance = author
        .call("getbalance", json!([]))
        .await
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(-1.0);
    drop(author);

    // B. The from-seed restore: same seed, birthday before the funding, its own backend instance.
    //    It never saw either transaction live, so everything must come from the chain.
    let mut restore_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("rpc port"));
    restore_cfg.transparent = true;
    restore_cfg.restore_mnemonic = Some(mnemonic);
    restore_cfg.birthday = Some(pre_fund_height.saturating_sub(1).max(1));
    let restore = Zecd::start(&restore_cfg)
        .await
        .expect("restore the wallet from seed");
    let tip = tip_height(&zebrad).await;
    restore
        .wait_until_synced(u64::from(tip), FUND_TIMEOUT)
        .await
        .expect("the restore scans to the tip");

    // Both halves must surface. The receive rides the block scan's transparent matcher; the spend
    // is only ever found by a `TransactionsInvolvingAddress` check of the funded address, so a
    // `receive=true send=false` failure here is precisely the spend-discovery gap.
    let deadline = Instant::now() + RECOVER_TIMEOUT;
    loop {
        let txs = restore
            .call("listtransactions", json!(["*", 100]))
            .await
            .expect("listtransactions on the restore");
        let arr = txs.as_array().cloned().unwrap_or_default();
        let has_receive = arr
            .iter()
            .any(|t| t["category"] == "receive" && t["address"] == json!(taddr));
        let has_send = arr
            .iter()
            .any(|t| t["category"] == "send" && t["txid"] == json!(spend_txid));
        if has_receive && has_send {
            break;
        }
        if Instant::now() >= deadline {
            // Report the balance divergence alongside the missing history: it is the difference
            // between "the history view is incomplete" and "the wallet believes it holds money
            // it has already spent", which is the part that actually matters to an operator.
            let restore_balance = restore
                .call("getbalance", json!([]))
                .await
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(-1.0);
            let unspent = restore
                .call("listunspent", json!([0]))
                .await
                .ok()
                .and_then(|v| v.as_array().map(|a| a.len()))
                .unwrap_or(0);
            panic!(
                "offline receive+spend history not recovered: \
                 receive={has_receive} send={has_send} (funded address {taddr}, spend \
                 {spend_txid}). Restored balance {restore_balance} vs the authoring wallet's \
                 {author_balance}; restore reports {unspent} unspent output(s). History: {txs}"
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The node's current best height.
async fn tip_height(zebrad: &Zebrad) -> u32 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("height") as u32
}
