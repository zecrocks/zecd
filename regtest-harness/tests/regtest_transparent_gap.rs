//! Transparent **gap-limit** restore end-to-end: prove that the configured external transparent
//! gap limit is what actually bounds stateless-restore recovery - the property that backs the
//! `[pools] transparent_gap_limit` knob and the "RPC client hands out N addresses, only a high
//! one gets funded" scenario.
//!
//! Why this exists: `regtest_transparent.rs` funds the *first* handed-out address (index 0), which
//! is within any gap limit, and never restores - so it can't catch a regression in the gap
//! plumbing (e.g. the configured limit being dropped on the floor, leaving the librustzcash
//! default, or transparent discovery scanning everything regardless). This test funds a transparent
//! address **beyond** a small gap and then rebuilds the wallet from seed twice:
//!
//!   * restore with `transparent_gap_limit = 3` (well below the funded index) → the receive is
//!     **missed** (the scan never exposes/queries that index), so the balance stays 0; and
//!   * restore with `transparent_gap_limit = 25` (above the funded index) → the **same** receive
//!     is **recovered**.
//!
//! The miss case is the load-bearing assertion: it fails both if the configured gap is ignored
//! (the librustzcash default of 20 would *find* an index < 20) and if discovery scans unbounded.
//! Indices are small/explicit for CI speed, but the mechanism is identical at index 999 of 1000 -
//! you size the gap limit to your maximum outstanding-unfunded address count.
//!
//! Skips cleanly unless `ZEBRAD_BIN`/`LIGHTWALLETD_BIN`/`DEVTOOL_BIN` are all set. Standard tier:
//! it's the load-bearing guard for the (recently-broken) transparent receive-discovery path plus
//! the gap-limit / initial-scan logic, so it runs on every regtest CI run rather than only the weekly tier.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const FUND_ZATOSHIS: u64 = 100_000_000; // 1 ZEC
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

/// Number of transparent addresses the "RPC client" hands out before any is funded. Only the last
/// (highest-index) one receives funds, so the funded index is `NUM_ADDRESSES - 1`.
const NUM_ADDRESSES: usize = 9;
/// Below the funded index (and below librustzcash's default of 20, so the miss also catches the
/// configured gap being ignored).
const SMALL_GAP: u32 = 3;
/// Above the funded index, so the restore re-exposes and queries it.
const LARGE_GAP: u32 = 25;

#[tokio::test]
async fn regtest_transparent_gap_limit_bounds_restore_recovery() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_transparent_gap_limit_bounds_restore_recovery: set ZEBRAD_BIN, \
             LIGHTWALLETD_BIN and DEVTOOL_BIN to run the transparent gap-limit e2e (see README.md)."
        );
        return;
    };

    // 1-4. Funder bring-up (identical to regtest_transparent): mine + mature + shield the funder.
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

    // 5. The "authoring" wallet: transparent enabled (default gap). It hands out NUM_ADDRESSES bare
    //    transparent addresses; because each is explicitly exposed by getnewaddress, the authoring
    //    instance can receive on any of them regardless of the gap.
    let zecd_rpc = pick_port().expect("pick zecd rpc port");
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, zecd_rpc);
    cfg.transparent = true;
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start the authoring zecd with transparent receiving");
    let mnemonic = zecd
        .mnemonic
        .clone()
        .expect("a fresh init prints the generated mnemonic");

    // Hand out NUM_ADDRESSES sequential transparent addresses; fund only the last (highest index).
    let mut addresses = Vec::with_capacity(NUM_ADDRESSES);
    for _ in 0..NUM_ADDRESSES {
        let a = zecd
            .call("getnewaddress", json!(["", "transparent"]))
            .await
            .expect("getnewaddress transparent")
            .as_str()
            .expect("address string")
            .to_string();
        assert!(a.starts_with("tm"), "bare t-addr expected, got {a}");
        addresses.push(a);
    }
    let distinct: std::collections::HashSet<&String> = addresses.iter().collect();
    assert_eq!(
        distinct.len(),
        NUM_ADDRESSES,
        "getnewaddress must advance the transparent index each call (sequential external chain): {addresses:?}"
    );
    let funded_addr = addresses.last().expect("at least one address").clone();

    // Wait until the authoring instance is caught up (mempool stream open) before funding.
    wait_for_ready(&zecd, FUND_TIMEOUT).await;

    // Birthday anchor for the later restores: the chain height just before the funding tx.
    let pre_fund_height = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount before funding")
        .as_u64()
        .expect("height") as u32;

    // 6. Fund the high-index transparent address and confirm it.
    funder
        .send(lwd.grpc_port, &funded_addr, FUND_ZATOSHIS)
        .expect("send to the high-index transparent address");
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the transparent receive");

    let tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount after funding")
        .as_u64()
        .expect("height");

    // The authoring instance finds the funds (the funded index is explicitly exposed).
    wait_for_balance_at_least(&zecd, 1.0, FUND_TIMEOUT).await;
    let authored_balance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance on the authoring instance")
        .as_f64()
        .expect("balance number");
    assert!(
        (authored_balance - 1.0).abs() < 1e-8,
        "authoring instance sees the 1-ZEC transparent receive at the high index: {authored_balance}"
    );
    drop(zecd);

    // 7. Restore with TOO SMALL a gap: the scan exposes only indices 0..SMALL_GAP, never reaches the
    //    funded index, so the funds are permanently missed. This is the load-bearing assertion - it
    //    fails if the configured gap is ignored (the default of 20 would find an index < 20) or if
    //    transparent discovery scans unbounded.
    let mut miss_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    miss_cfg.transparent = true;
    miss_cfg.transparent_gap_limit = Some(SMALL_GAP);
    miss_cfg.restore_mnemonic = Some(mnemonic.clone());
    miss_cfg.birthday = Some(pre_fund_height);
    let miss = Zecd::start(&miss_cfg)
        .await
        .expect("restore zecd with a too-small transparent gap limit");
    assert_eq!(
        miss.call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo")["transparent"]["gap_limit"],
        json!(SMALL_GAP),
        "the restored wallet reports the configured (small) gap limit"
    );
    miss.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the small-gap restore scans to the tip");
    // The block scan has reached the tip; give the caught-up enhancement pass (which services the
    // transparent getaddresstxids requests) a settle window, then assert the funds stayed missed.
    assert_balance_stays_zero(&miss, Duration::from_secs(20)).await;
    drop(miss);

    // 8. Restore with a SUFFICIENT gap: the same seed, same chain - now the scan exposes the funded
    //    index, so getaddressutxos finds the receive and the balance comes back.
    let mut find_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    find_cfg.transparent = true;
    find_cfg.transparent_gap_limit = Some(LARGE_GAP);
    find_cfg.restore_mnemonic = Some(mnemonic.clone());
    find_cfg.birthday = Some(pre_fund_height);
    let find = Zecd::start(&find_cfg)
        .await
        .expect("restore zecd with a sufficient transparent gap limit");
    find.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the large-gap restore scans to the tip");
    wait_for_balance_at_least(&find, 1.0, FUND_TIMEOUT).await;
    let recovered = find
        .call("getbalance", json!([]))
        .await
        .expect("getbalance on the recovered instance")
        .as_f64()
        .expect("balance number");
    assert!(
        (recovered - 1.0).abs() < 1e-8,
        "a gap limit above the funded index recovers the 1-ZEC transparent receive: {recovered}"
    );
    drop(find);

    // 9. Decouple initial scan depth from the steady-state gap. Restore with a SMALL gap
    //    (which alone misses the funded index, as step 7 proved) but a large `transparent_initial_scan`.
    //    The pre-exposure of indices 0..INITIAL_SCAN means the receive is recovered *without* paying
    //    for a large sliding gap. This is the exchange's "10 000 addresses, only #9000 funded" case
    //    at small indices.
    let mut a18_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    a18_cfg.transparent = true;
    a18_cfg.transparent_gap_limit = Some(SMALL_GAP); // too small on its own (step 7 missed)
    a18_cfg.transparent_initial_scan = Some(LARGE_GAP); // but pre-exposes past the funded index
    a18_cfg.restore_mnemonic = Some(mnemonic);
    a18_cfg.birthday = Some(pre_fund_height);
    let a18 = Zecd::start(&a18_cfg)
        .await
        .expect("restore zecd with a small gap + large initial scan depth");
    assert_eq!(
        a18.call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo")["transparent"]["gap_limit"],
        json!(SMALL_GAP),
        "the initial-scan wallet keeps the small steady-state gap"
    );
    a18.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the initial-scan restore scans to the tip");
    wait_for_balance_at_least(&a18, 1.0, FUND_TIMEOUT).await;
    let a18_balance = a18
        .call("getbalance", json!([]))
        .await
        .expect("getbalance on the initial-scan instance")
        .as_f64()
        .expect("balance number");
    assert!(
        (a18_balance - 1.0).abs() < 1e-8,
        "initial_scan recovers the high-index receive despite the small gap: {a18_balance}"
    );

    lwd.stop();
    drop(a18);
    // `zebrad` and `funder` clean up on drop.
}

/// Block until zecd reports its upstream peer `ready` (caught up; the mempool stream is open).
async fn wait_for_ready(zecd: &Zecd, timeout: Duration) {
    let deadline = Instant::now() + timeout;
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
}

/// Poll `getbalance` until it reaches at least `target` ZEC, or panic on timeout.
async fn wait_for_balance_at_least(zecd: &Zecd, target: f64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= target {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never reached {target} ZEC (got {bal})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Assert the balance stays at 0 for the whole window - a positive check that the beyond-gap
/// receive is never discovered (not merely "not yet"). The wallet is already synced to the tip, so
/// the caught-up enhancement passes run within this window; if a regression exposed the funded
/// index, the funds would appear here (the sufficient-gap restore finds them in comparable time).
async fn assert_balance_stays_zero(zecd: &Zecd, window: Duration) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        assert!(
            bal < 1e-8,
            "a receive beyond the configured gap limit must not be recovered, but balance = {bal}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
