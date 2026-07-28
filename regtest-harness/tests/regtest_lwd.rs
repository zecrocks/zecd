//! Light-mode regtest end-to-end: the zecd under test runs against a **lightwalletd** upstream
//! (`server = "http://127.0.0.1:<grpc>"`), exercising the whole light path - init (tree state +
//! tip over gRPC), compact-block sync via `GetBlockRange`, 0-conf via the native
//! `GetMempoolStream`, memo enhancement via `GetTransaction`, a real Orchard spend broadcast
//! via `SendTransaction`, an upstream outage/reconnect, and the full `conformance.py`
//! wire-format suite against the funded light-mode daemon.
//!
//! A second zecd instance runs against the same chain **directly on zebrad's JSON-RPC**, and
//! the two must agree on chain state (`getblockcount`, `getbestblockhash`) at every checkpoint.
//! That agreement is the system-level proof that the two backends derive the same chain view (a
//! byte-order or conversion bug would skew hashes, balances, or history). This is the mirror of the
//! pre-zebra-only `regtest_zebra.rs` equivalence test.
//!
//! The **offline-window sweep leg** then proves backend behavior-identity for the one case
//! only a per-address history query can recover: a transparent output received *and spent*
//! while zecd wasn't watching. An authoring (zebra-backed) instance receives-then-spends on a
//! t-addr and is stopped; a light-mode restore of the same seed must still show the full
//! receive+send history. Runs against `$LIGHTWALLETD_BIN`, and again against
//! `$LIGHTWALLETD_LEGACY_BIN` when set (a pre-versioned-protocol server, where the sweep -
//! not the block scan - is what recovers the history).
//!
//! Unlike the suites that honor `ZECD_REGTEST_BACKEND`, this test is always light-mode (it IS
//! the lightwalletd e2e). Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and
//! `DEVTOOL_BIN` are all set.

use std::path::Path;
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
/// Generous: covers a full scan plus Orchard proving on the spend.
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_lwd_e2e() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_lwd_e2e: set ZEBRAD_BIN, LIGHTWALLETD_BIN and DEVTOOL_BIN to run \
             the light-mode e2e (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // 1. One chain, funded exactly like the funded e2e: mine the funder's coinbases, then
    //    restart mining to a throwaway address so they mature.
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

    // 2. The funder keeps its own lightwalletd (fault isolation: outage phases below hit only
    //    the zecd-side instance).
    let funder_lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start the funder's lightwalletd");
    let funder = Funder::init(&devtool_bin, funder_lwd.grpc_port).expect("initialise funder");
    funder
        .sync(funder_lwd.grpc_port)
        .expect("funder sync (coinbase)");
    funder
        .shield(funder_lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder
        .sync(funder_lwd.grpc_port)
        .expect("funder sync (shielded)");

    // 3. The system under test: zecd in light mode, on its own dedicated lightwalletd.
    //    `Zecd::start` also runs `zecd init` against the light endpoint (tip + tree state
    //    over gRPC).
    let zecd_lwd_upstream = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start zecd's lightwalletd");
    let mut lwd_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("rpc port"));
    lwd_cfg.lightwalletd_grpc_port = Some(zecd_lwd_upstream.grpc_port);
    let zecd = Zecd::start(&lwd_cfg)
        .await
        .expect("start zecd in light mode");

    // The comparison instance: identical zecd, directly against zebrad.
    let zebra_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("rpc port"));
    let zecd_zebra = Zecd::start(&zebra_cfg)
        .await
        .expect("start the zebra-backed comparison zecd");

    // 4. Both instances scan the same chain to the same tip…
    let tip = zebrad
        .rpc("getblockchaininfo", json!([]))
        .await
        .expect("zebrad getblockchaininfo")["blocks"]
        .as_u64()
        .expect("blocks is a number");
    zecd.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("light-mode zecd syncs to the tip");
    zecd_zebra
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("zebra-backed zecd syncs to the tip");

    // …and must agree on what that chain is. This pins the lightwalletd backend's hash byte
    // order and tip handling against the zebra backend's, end to end.
    assert_chain_views_agree(&zecd, &zecd_zebra).await;
    let info = zecd
        .call("getblockchaininfo", json!([]))
        .await
        .expect("getblockchaininfo");
    assert_eq!(info["chain"].as_str(), Some("regtest"), "{info}");

    // The single "peer" is the light upstream.
    let peers = zecd
        .call("getpeerinfo", json!([]))
        .await
        .expect("getpeerinfo");
    let addr = peers[0]["addr"].as_str().unwrap_or_default();
    assert!(
        addr.starts_with("lightwalletd "),
        "getpeerinfo.addr should name the light upstream, got {addr}"
    );

    // 5. Fund the light-mode wallet with a real Orchard note carrying a memo.
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();
    assert!(zecd_ua.starts_with("uregtest1"), "got {zecd_ua}");
    let memo = "light mode e2e memo";
    funder
        .send_with_memo(funder_lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS, Some(memo))
        .expect("send Orchard funds (with memo) to zecd");

    // 0-conf: before anything is mined, the native GetMempoolStream must surface the incoming
    // payment.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let unconfirmed = zecd
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
            "GetMempoolStream never surfaced the incoming 0-conf payment"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Mine it past the untrusted-confirmations depth (10) and verify the receive + memo.
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm funding send");
    let deadline = Instant::now() + FUND_TIMEOUT;
    let funding_txid = loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal > 0.0 {
            assert_eq!(bal, 1.0, "the funded 1 ZEC is spendable");
            let txs = zecd
                .call("listtransactions", json!([]))
                .await
                .expect("listtransactions");
            let recv = txs
                .as_array()
                .expect("array")
                .iter()
                .find(|t| t["category"] == "receive")
                .unwrap_or_else(|| panic!("expected a receive in history: {txs}"))
                .clone();
            break recv["txid"].as_str().expect("txid").to_string();
        }
        if Instant::now() >= deadline {
            panic!("light-mode zecd did not see the funded Orchard note within {FUND_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    // The memo needs the enhancement pass (full tx via GetTransaction) if the mempool stream
    // missed the tx; poll briefly.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let gt = zecd
            .call("gettransaction", json!([funding_txid]))
            .await
            .expect("gettransaction on the funding tx");
        let memo_ok = gt["details"]
            .as_array()
            .is_some_and(|d| d.iter().any(|e| e["memoStr"] == json!(memo)));
        if memo_ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the received memo never surfaced through enhancement: {gt}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 6. Spend: a real Orchard send back to the funder, broadcast via SendTransaction,
    //    confirmed by mining.
    let funder_ua = funder.unified_address().expect("funder unified address");
    let txid = zecd
        .call("sendtoaddress", json!([funder_ua, 0.4]))
        .await
        .expect("sendtoaddress through the light backend");
    let txid = txid.as_str().expect("txid is a string").to_string();
    assert_eq!(txid.len(), 64);
    mine_until_confirmed(&zebrad, &zecd, &txid, "light-mode send").await;

    // 7. Outage + reconnect: kill zecd's lightwalletd; the daemon must notice (conn_state
    //    leaves "ready") and, when a fresh lightwalletd comes back on the same port, reconnect
    //    and catch up. (A fresh data dir re-ingests the regtest chain from zebra in seconds.)
    let grpc_port = zecd_lwd_upstream.grpc_port;
    zecd_lwd_upstream.stop();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let peers = zecd
            .call("getpeerinfo", json!([]))
            .await
            .expect("getpeerinfo");
        let state = peers[0]["conn_state"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if state != "ready" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never noticed the dead light upstream: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let zecd_lwd_upstream = Lightwalletd::start_on(&lwd_bin, zebrad.rpc_port, grpc_port)
        .await
        .expect("restart zecd's lightwalletd on the same port");
    zebrad.generate_blocks(2).await.expect("advance the chain");
    let tip = zecd_zebra_tip(&zebrad).await;
    zecd.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("light-mode zecd reconnects and catches up");
    drop(zecd_lwd_upstream);

    // 8. After all activity, the two instances still agree on the chain.
    let tip = zecd_zebra_tip(&zebrad).await;
    zecd.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("light-mode zecd at the final tip");
    zecd_zebra
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("comparison zecd catches up");
    assert_chain_views_agree(&zecd, &zecd_zebra).await;

    // Note: zecd's lightwalletd was dropped above, so the conformance run below exercises the
    // daemon with a dead upstream for chain-independent methods too - but conformance needs a
    // live wallet view, so bring an upstream back first.
    let zecd_lwd_upstream = Lightwalletd::start_on(&lwd_bin, zebrad.rpc_port, grpc_port)
        .await
        .expect("bring the light upstream back for conformance");

    // 9. The full Bitcoin-Core wire-format suite against the funded light-mode daemon.
    run_conformance(lwd_cfg.rpc_port, &lwd_cfg.rpc_user, &lwd_cfg.rpc_password);
    drop(zecd_lwd_upstream);
    drop(zecd);
    drop(zecd_zebra);

    // 10. Offline-window sweep: behavior-identity for received-and-spent-while-offline
    //     transparent history. Once on the primary lightwalletd, and once on the legacy
    //     (pre-versioned-protocol) binary when provided - there the block scan carries no
    //     transparent data, so the sweep is the only thing that can recover the history.
    offline_sweep_leg(&mut zebrad, &funder, &funder_lwd, &lwd_bin, "primary").await;
    if let Some(legacy_bin) = resolve_bin("LIGHTWALLETD_LEGACY_BIN") {
        offline_sweep_leg(&mut zebrad, &funder, &funder_lwd, &legacy_bin, "legacy").await;
    } else {
        eprintln!("NOTE: LIGHTWALLETD_LEGACY_BIN not set - skipping the legacy-server sweep leg");
    }
}

/// The offline-window sweep proof: an authoring (zebra-backed) wallet receives on a t-addr and
/// spends it, then goes away; a light-mode restore of the same seed - which never saw either
/// tx live - must recover the full receive+send pair in history. On a legacy server neither
/// the UTXO refresh (the output is spent) nor compact blocks (no transparent data) can see it;
/// the per-address `GetTaddressTxids` sweep is what makes this pass.
async fn offline_sweep_leg(
    zebrad: &mut Zebrad,
    funder: &Funder,
    funder_lwd: &Lightwalletd,
    lwd_bin: &Path,
    label: &str,
) {
    eprintln!("== offline-sweep leg ({label}) ==");
    // A. The authoring wallet: zebra-backed, transparent receiving + fully-transparent spends.
    let pre_fund_height = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("height") as u32;
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

    // Fund the t-addr and wait for the (mined) receive.
    funder
        .send(funder_lwd.grpc_port, &taddr, FUND_ZATOSHIS / 2)
        .expect("fund the authoring wallet's t-addr");
    zebrad
        .generate_blocks(2)
        .await
        .expect("mine the funding tx");
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let tip = zecd_zebra_tip(zebrad).await;
        author
            .wait_until_synced(tip, Duration::from_secs(30))
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

    // Spend from the t-addr (fully transparent), confirm, and stop the authoring wallet.
    let funder_taddr =
        Funder::derive_transparent_address(&resolve_bin("DEVTOOL_BIN").expect("devtool bin"))
            .expect("funder t-addr");
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
                let tip = zecd_zebra_tip(zebrad).await;
                author
                    .wait_until_synced(tip, Duration::from_secs(30))
                    .await
                    .expect("author rescans");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("fully-transparent spend failed: {e}"),
        }
    };
    mine_until_confirmed(zebrad, &author, &spend_txid, "authoring t-spend").await;
    drop(author);

    // B. The light-mode restore: same seed, birthday before the funding, its own lightwalletd.
    let restore_lwd = Lightwalletd::start(lwd_bin, zebrad.rpc_port)
        .await
        .expect("start the restore's lightwalletd");
    let mut restore_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("rpc port"));
    restore_cfg.lightwalletd_grpc_port = Some(restore_lwd.grpc_port);
    restore_cfg.transparent = true;
    restore_cfg.restore_mnemonic = Some(mnemonic);
    restore_cfg.birthday = Some(pre_fund_height.saturating_sub(1).max(1));
    let restore = Zecd::start(&restore_cfg)
        .await
        .expect("restore the wallet in light mode");
    let tip = zecd_zebra_tip(zebrad).await;
    restore
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the light-mode restore scans to the tip");

    // The receive+send pair must surface - recovered by the offline sweep (legacy server) or
    // the transparent-carrying block scan (versioned server); either way, identical history to
    // what the zebra-backed authoring instance recorded.
    let deadline = Instant::now() + Duration::from_secs(90);
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
        assert!(
            Instant::now() < deadline,
            "offline receive+spend history not recovered ({label}): \
             receive={has_receive} send={has_send}: {txs}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    eprintln!("== offline-sweep leg ({label}) OK ==");
}

async fn zecd_zebra_tip(zebrad: &Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount")
        .as_u64()
        .expect("tip height")
}

/// The light-mode and zebra-backed instances must report the identical chain.
async fn assert_chain_views_agree(lwd: &Zecd, zebra: &Zecd) {
    let (hl, hz) = (
        lwd.block_count().await.expect("light-mode getblockcount"),
        zebra
            .block_count()
            .await
            .expect("zebra-backed getblockcount"),
    );
    assert_eq!(hl, hz, "block counts diverge between backends");
    let bl = lwd
        .call("getbestblockhash", json!([]))
        .await
        .expect("light-mode getbestblockhash");
    let bz = zebra
        .call("getbestblockhash", json!([]))
        .await
        .expect("zebra-backed getbestblockhash");
    assert_eq!(bl, bz, "best block hashes diverge between backends");
    assert_eq!(
        bl.as_str().map(str::len),
        Some(64),
        "best block hash is display hex: {bl}"
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

/// Run `scripts/conformance.py` against the light-mode daemon (same helper as the funded
/// e2e). Skips with a notice if `python3` isn't available; CI always has it.
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
