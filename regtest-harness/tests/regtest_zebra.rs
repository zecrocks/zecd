//! Zebra-backend regtest end-to-end: `zecd` runs with **no lightwalletd in its server list**
//! (`servers = ["zebra://127.0.0.1:<rpc>"]`), deriving everything from zebrad's JSON-RPC -
//! init (tree state + tip), subtree roots, compact-block sync (raw-block parsing +
//! local CompactBlock conversion), 0-conf mempool visibility (the `getrawmempool` poller),
//! a real Orchard spend broadcast via `sendrawtransaction`, and the full `conformance.py`
//! wire-format suite against the funded daemon.
//!
//! A second zecd instance runs against the same chain **through lightwalletd**, and the two
//! must agree on chain state (`getblockcount`, `getbestblockhash`) at every checkpoint -
//! the system-level proof that the zebra backend derives the same chain view lightwalletd
//! serves (a byte-order or conversion bug would skew hashes, balances, or history).
//!
//! The chain/funding choreography matches `regtest_funded.rs`: mine transparent coinbase to
//! the devtool funder → mature → shield to Orchard → send to zecd. The funder itself still
//! uses lightwalletd (zcash-devtool only speaks the gRPC protocol); only the zecd under
//! test is lightwalletd-free.
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// See `regtest_funded.rs` for the choreography these mirror.
const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
/// Generous: zebra-backed sync is two RPCs per block, plus Orchard proving on the spend.
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_zebra_e2e() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_zebra_e2e: set ZEBRAD_BIN, LIGHTWALLETD_BIN and DEVTOOL_BIN \
             to run the zebra-backed e2e (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // 1. One chain, funded exactly like the lightwalletd e2e: mine the funder's coinbases,
    //    then restart mining to a throwaway address so they mature.
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

    // 2. lightwalletd serves the funder (devtool is gRPC-only) and the comparison zecd.
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");
    let funder = Funder::init(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 3. The system under test: zecd direct against zebrad, no lightwalletd to fall back to.
    //    `Zecd::start` also runs `zecd init` against the zebra endpoint (tip + tree state).
    let zebra_cfg = ZecdConfig::new_zebra(zebrad.rpc_port, pick_port().expect("rpc port"));
    let zecd_zebra = Zecd::start(&zebra_cfg)
        .await
        .expect("start zecd directly against zebrad");

    // The comparison instance: identical zecd, but fed through lightwalletd.
    let lwd_cfg = ZecdConfig::new(lwd.grpc_port, pick_port().expect("rpc port"));
    let zecd_lwd = Zecd::start(&lwd_cfg)
        .await
        .expect("start the lightwalletd-backed comparison zecd");

    // 4. Both instances scan the same chain to the same tip…
    let tip = zebrad
        .rpc("getblockchaininfo", json!([]))
        .await
        .expect("zebrad getblockchaininfo")["blocks"]
        .as_u64()
        .expect("blocks is a number");
    zecd_zebra
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("zebra-backed zecd syncs to the tip");
    zecd_lwd
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("lightwalletd-backed zecd syncs to the tip");

    // …and must agree on what that chain is. This pins the zebra backend's hash byte order
    // and tip handling against lightwalletd's, end to end.
    assert_chain_views_agree(&zecd_zebra, &zecd_lwd).await;
    let info = zecd_zebra
        .call("getblockchaininfo", json!([]))
        .await
        .expect("getblockchaininfo");
    assert_eq!(info["chain"].as_str(), Some("regtest"), "{info}");

    // 5. Fund the zebra-backed wallet with a real Orchard note.
    let zecd_ua = zecd_zebra
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();
    assert!(zecd_ua.starts_with("uregtest1"), "got {zecd_ua}");
    funder
        .send(lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS)
        .expect("send Orchard funds to zecd");

    // 0-conf: before anything is mined, the mempool poller must surface the incoming
    // payment (trial-decrypted from `getrawmempool`+`getrawtransaction`) just like the
    // lightwalletd mempool stream does.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let unconfirmed = zecd_zebra
            .call("getunconfirmedbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if unconfirmed > 0.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the zebra mempool poller never surfaced the incoming 0-conf payment"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Mine it in past the untrusted-confirmations depth (10) and verify the receive.
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm funding send");
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let bal = zecd_zebra
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal > 0.0 {
            assert_eq!(bal, 1.0, "the funded 1 ZEC is spendable");
            break;
        }
        if Instant::now() >= deadline {
            panic!("zebra-backed zecd did not see the funded Orchard note within {FUND_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let txs = zecd_zebra
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert!(
        txs.as_array()
            .expect("array")
            .iter()
            .any(|t| t["category"] == "receive"),
        "expected a receive in history: {txs}"
    );

    // 6. Spend: a real Orchard send back to the funder, broadcast via `sendrawtransaction`,
    //    confirmed by mining (rebroadcast/scan loop sees it through the zebra backend).
    let funder_ua = funder.unified_address().expect("funder unified address");
    let txid = zecd_zebra
        .call("sendtoaddress", json!([funder_ua, 0.4]))
        .await
        .expect("sendtoaddress through the zebra backend");
    let txid = txid.as_str().expect("txid is a string").to_string();
    assert_eq!(txid.len(), 64);
    let gt = zecd_zebra
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction on the unmined send");
    assert_eq!(gt["amount"].as_f64(), Some(-0.4), "{gt}");
    assert_eq!(gt["confirmations"].as_i64(), Some(0), "{gt}");
    mine_until_confirmed(&zebrad, &zecd_zebra, &txid, "zebra-backed send").await;

    // 7. After all activity, the two instances still agree on the chain.
    let tip = zecd_zebra.block_count().await.expect("getblockcount");
    zecd_lwd
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("comparison zecd catches up");
    assert_chain_views_agree(&zecd_zebra, &zecd_lwd).await;

    // 8. The full Bitcoin-Core wire-format suite against the funded zebra-backed daemon.
    run_conformance(
        zebra_cfg.rpc_port,
        &zebra_cfg.rpc_user,
        &zebra_cfg.rpc_password,
    );
}

/// The zebra-backed and lightwalletd-backed instances must report the identical chain.
async fn assert_chain_views_agree(zebra: &Zecd, lwd: &Zecd) {
    let (hz, hl) = (
        zebra
            .block_count()
            .await
            .expect("zebra-backed getblockcount"),
        lwd.block_count().await.expect("lwd-backed getblockcount"),
    );
    assert_eq!(hz, hl, "block counts diverge between backends");
    let bz = zebra
        .call("getbestblockhash", json!([]))
        .await
        .expect("zebra-backed getbestblockhash");
    let bl = lwd
        .call("getbestblockhash", json!([]))
        .await
        .expect("lwd-backed getbestblockhash");
    assert_eq!(bz, bl, "best block hashes diverge between backends");
    assert_eq!(
        bz.as_str().map(str::len),
        Some(64),
        "best block hash is display hex: {bz}"
    );
}

/// Mine one block at a time (giving the scan loop time between blocks) until zecd reports
/// the tx confirmed. Panics after ~30 rounds.
async fn mine_until_confirmed(zebrad: &Zebrad, zecd: &Zecd, txid: &str, what: &str) {
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        zebrad.generate_blocks(1).await.expect("mine a block");
        let gt = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction while polling for confirmation");
        if gt["confirmations"].as_i64().unwrap_or(0) >= 1 {
            return;
        }
    }
    panic!("{what}: tx {txid} did not confirm within the mining budget");
}

/// Run `scripts/conformance.py` against the zebra-backed daemon (same helper as the funded
/// lightwalletd e2e). Skips with a notice if `python3` isn't available; CI always has it.
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
