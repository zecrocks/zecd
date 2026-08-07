//! Transparent **gap-limit** restore end-to-end: prove that the configured external transparent
//! gap limit is what actually bounds stateless-restore recovery - the property that backs the
//! `[pools] transparent_gap_limit` knob and the "RPC client hands out N addresses, only a high
//! one gets funded" scenario.
//!
//! Why this exists: `regtest_transparent.rs` funds the *first* handed-out address, which is
//! within any gap limit, and never restores - so it can't catch a regression in the gap
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
//! **The authoring wallet's mnemonic is pinned** (the checked-in development phrase), not
//! generated per run. Account creation derives and exposes the account's *default address*, whose
//! diversifier index is the seed's first all-receivers-valid index - 0 for only about half of all
//! seeds. A per-run mnemonic therefore made the restore's issuance frontier (and with it every
//! index this test reasons about) a per-run random variable: seeds whose default address landed at
//! index >= 3 tripped the fresh-restore assertions below at random (CI saw frontiers 5, 6 and 10).
//! The pinned phrase's default address sits at index 0 - asserted offline by
//! `open.rs::account_creation_respects_the_configured_transparent_gap_limit` and re-checked here
//! at runtime via `getaddressinfo.address_index` - which makes every index in this file exact:
//! issuance starts at external index 1 (index 0 is the default address) and the funded address is
//! index `NUM_ADDRESSES`.
//!
//! It then proves the **horizon composition** (the knobs compose instead of the gap having to
//! swallow the floor): on the small-gap + `transparent_initial_scan` restore, `getnewaddress`
//! keeps issuing at the floor index without error, a payment there is received live, and a final
//! from-seed restore with the **same** small-gap config recovers it via the matcher's gap
//! lookahead - the `initial_scan = 70000, gap_limit = 1000` exchange shape at CI-sized indices.
//!
//! Skips cleanly unless `ZEBRAD_BIN` is set. Standard tier:
//! it's the load-bearing guard for the (recently-broken) transparent receive-discovery path plus
//! the gap-limit / A18 logic, so it runs on every regtest CI run rather than only the weekly tier.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    attach_backend, pick_port, resolve_node_bin, start_funded_chain, RegtestNode, Zecd, ZecdConfig,
};

const FUND_ZATOSHIS: u64 = 100_000_000; // 1 ZEC
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

/// The checked-in development phrase (testnet-only, valueless). Pinned so the
/// default-address index (0) and with it every external index in this test are deterministic;
/// `open.rs::account_creation_respects_the_configured_transparent_gap_limit` asserts the
/// index-0 property offline, and the `getaddressinfo` checks below re-verify it live.
const AUTHORING_MNEMONIC: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
     midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
     moment stage";

/// Number of transparent addresses the "RPC client" hands out before any is funded. The account's
/// default address occupies external index 0, so `getnewaddress` hands out indices
/// `1..=NUM_ADDRESSES`; only the last is funded, so the funded index is `NUM_ADDRESSES`.
const NUM_ADDRESSES: usize = 9;
/// The funded address's external child index (see [`NUM_ADDRESSES`]).
const FUNDED_INDEX: u64 = NUM_ADDRESSES as u64;
/// Below the funded index (and below librustzcash's default of 20, so the miss also catches the
/// configured gap being ignored).
const SMALL_GAP: u32 = 3;
/// Above the funded index, so the restore re-exposes and queries it.
const LARGE_GAP: u32 = 25;

#[tokio::test]
async fn regtest_transparent_gap_limit_bounds_restore_recovery() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_transparent_gap_limit_bounds_restore_recovery: set {} to run the \
             transparent gap-limit e2e.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // 1-4. Bring up the chain and its funding wallet: seed blocks to a throwaway address,
    //      create the funder against them, mine and mature its coinbase, shield it into
    //      Orchard. See `start_funded_chain`.
    let (zebrad, funder) = start_funded_chain(&zebrad_bin)
        .await
        .expect("bring up a funded regtest chain");

    // 5. The "authoring" wallet: transparent enabled (default gap), restored from the pinned
    //    phrase at the current tip (the phrase has no regtest history, so this is equivalent to a
    //    fresh init with a known seed). It hands out NUM_ADDRESSES bare transparent addresses;
    //    because each is explicitly exposed by getnewaddress, the authoring instance can receive
    //    on any of them regardless of the gap.
    let authoring_birthday = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount before the authoring wallet")
        .as_u64()
        .expect("height") as u32;
    let zecd_rpc = pick_port().expect("pick zecd rpc port");
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, zecd_rpc);
    cfg.transparent = true;
    cfg.restore_mnemonic = Some(AUTHORING_MNEMONIC.to_string());
    cfg.birthday = Some(authoring_birthday);
    let _zecd_lwd = attach_backend(&mut cfg, zebrad.rpc_port)
        .await
        .expect("attach zecd backend");
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start the authoring zecd with transparent receiving");

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

    // Verify the index accounting this whole test rests on: the default address holds index 0
    // (the pinned phrase's default-address index - the reason the phrase is pinned), so issuance
    // ran 1..=NUM_ADDRESSES and the funded address sits exactly at FUNDED_INDEX. If a future
    // change shifts issuance (or the phrase), this fails here with the real indices rather than
    // as a mysterious miss/find inversion later.
    let first_index = address_index(&zecd, &addresses[0]).await;
    assert_eq!(
        first_index, 1,
        "issuance must start at external index 1 - index 0 is the account default address \
         (pinned phrase); a different value means the index accounting below is off"
    );
    let funded_index = address_index(&zecd, &funded_addr).await;
    assert_eq!(
        funded_index, FUNDED_INDEX,
        "the funded (last handed-out) address must sit at index NUM_ADDRESSES"
    );

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
        .send(&funded_addr, FUND_ZATOSHIS)
        .await
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

    // 7. Restore with TOO SMALL a gap: the scan covers only indices 0..=SMALL_GAP (the account
    //    rows plus the gap lookahead past the default-address frontier), never reaches the funded
    //    index, so the funds are permanently missed. This is the load-bearing assertion - it
    //    fails if the configured gap is ignored (the default of 20 would find the funded index)
    //    or if transparent discovery scans unbounded.
    let mut miss_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    miss_cfg.transparent = true;
    miss_cfg.transparent_gap_limit = Some(SMALL_GAP);
    miss_cfg.restore_mnemonic = Some(AUTHORING_MNEMONIC.to_string());
    miss_cfg.birthday = Some(pre_fund_height);
    let _miss_lwd = attach_backend(&mut miss_cfg, zebrad.rpc_port)
        .await
        .expect("attach miss-restore backend");
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
    // Assert the *cause*, not a symptom-over-time. The matcher's live coverage runs
    // `gap_limit` past its issuance frontier (see the two-window note in the project docs); the funded
    // index must sit outside it, or this restore would credit a receive the gap limit says is
    // unrecoverable. Checking coverage directly is deterministic - the old
    // `assert_balance_stays_zero` watched a balance for 20 seconds, which made the guard a race
    // (it decided only whether the scan reached the funding block inside the window) and, when
    // it did fail, said nothing about why. With the pinned phrase the values are exact: the only
    // exposed external index is the default address (0), so the frontier is 1 and the lookahead
    // ends at SMALL_GAP.
    let t = miss
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo on the small-gap restore")["transparent"]
        .clone();
    assert_eq!(
        t["lookahead_from"].as_u64(),
        Some(1),
        "a fresh restore of the pinned phrase exposes only the default address (index 0), so \
         its issuance frontier is exactly 1: {t}"
    );
    let lookahead_through = t["lookahead_through"]
        .as_u64()
        .expect("lookahead_through present once the matcher is built");
    assert_eq!(
        lookahead_through,
        u64::from(SMALL_GAP),
        "the lookahead runs gap_limit past the frontier (1 + {SMALL_GAP} - 1): {t}"
    );
    assert!(
        lookahead_through < FUNDED_INDEX,
        "the small-gap restore's lookahead reaches index {lookahead_through}, covering the \
         funded index {FUNDED_INDEX}: a receive the configured gap limit says is unrecoverable \
         would be credited. transparent = {t}"
    );
    // The recovery horizon is gap_limit past the restore floor - here the default-address
    // frontier (1), since initial_scan is 0.
    assert_eq!(
        t["recovery_horizon"].as_u64(),
        Some(u64::from(SMALL_GAP) + 1),
        "initial_scan is 0 here, so the recovery horizon is the default-address frontier (1) \
         plus the gap limit: {t}"
    );
    // A restore that has issued nothing must sit entirely inside its own recovery horizon.
    assert_eq!(
        t["restorable"].as_bool(),
        Some(true),
        "a from-seed restore that has issued no addresses must report restorable = true: {t}"
    );
    // With coverage proven to exclude it, the balance must be zero - checked once, not watched.
    let bal = miss
        .call("getbalance", json!([]))
        .await
        .ok()
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    assert!(
        bal < 1e-8,
        "a receive beyond the configured gap limit must not be recovered, but balance = {bal} \
         (lookahead ends at {lookahead_through}, funded index {FUNDED_INDEX})"
    );
    drop(miss);

    // 8. Restore with a SUFFICIENT gap: the same seed, same chain - now the scan exposes the funded
    //    index, so the block-scan matcher finds the receive and the balance comes back.
    let mut find_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    find_cfg.transparent = true;
    find_cfg.transparent_gap_limit = Some(LARGE_GAP);
    find_cfg.restore_mnemonic = Some(AUTHORING_MNEMONIC.to_string());
    find_cfg.birthday = Some(pre_fund_height);
    let _find_lwd = attach_backend(&mut find_cfg, zebrad.rpc_port)
        .await
        .expect("attach find-restore backend");
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

    // 9. A18 - decouple initial scan depth from the steady-state gap. Restore with a SMALL gap
    //    (which alone misses the funded index, as step 7 proved) but a large `transparent_initial_scan`.
    //    The pre-exposure of indices 0..INITIAL_SCAN means the receive is recovered *without* paying
    //    for a large sliding gap. This is the exchange's "10 000 addresses, only #9000 funded" case
    //    at small indices.
    let mut a18_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    a18_cfg.transparent = true;
    a18_cfg.transparent_gap_limit = Some(SMALL_GAP); // too small on its own (step 7 missed)
    a18_cfg.transparent_initial_scan = Some(LARGE_GAP); // but pre-exposes past the funded index
    a18_cfg.restore_mnemonic = Some(AUTHORING_MNEMONIC.to_string());
    a18_cfg.birthday = Some(pre_fund_height);
    let _a18_lwd = attach_backend(&mut a18_cfg, zebrad.rpc_port)
        .await
        .expect("attach a18-restore backend");
    let a18 = Zecd::start(&a18_cfg)
        .await
        .expect("restore zecd with a small gap + large initial scan depth");
    assert_eq!(
        a18.call("getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo")["transparent"]["gap_limit"],
        json!(SMALL_GAP),
        "the A18 wallet keeps the small steady-state gap"
    );
    a18.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the A18 restore scans to the tip");
    wait_for_balance_at_least(&a18, 1.0, FUND_TIMEOUT).await;
    let a18_balance = a18
        .call("getbalance", json!([]))
        .await
        .expect("getbalance on the A18 instance")
        .as_f64()
        .expect("balance number");
    assert!(
        (a18_balance - 1.0).abs() < 1e-8,
        "initial_scan recovers the high-index receive despite the small gap: {a18_balance}"
    );

    // 10. Horizon composition - the gap anchors at the initial_scan floor rather than the floor
    //     having to fit inside the gap. On the A18 wallet (gap = 3, initial_scan = 25, all of
    //     0..25 pre-exposed and unfunded above the funded index) librustzcash's own
    //     funded-anchored window is exhausted, so before the gap lookahead this getnewaddress
    //     landed beyond every recovery mechanism: issued with an "UNRECOVERABLE" warning, and a
    //     from-seed restore really did miss funds sent to it. Now the floor index is within the
    //     recovery horizon (initial_scan + gap_limit = 28): it issues cleanly, receives live,
    //     and - the load-bearing assertion - a fresh restore with the SAME small-gap config
    //     recovers it via the matcher's in-memory lookahead of gap_limit indices past the floor.
    let floor_addr = a18
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress at the initial_scan floor (within the recovery horizon)")
        .as_str()
        .expect("address string")
        .to_string();
    assert!(
        floor_addr.starts_with("tm"),
        "bare t-addr expected, got {floor_addr}"
    );
    assert!(
        !addresses.contains(&floor_addr),
        "the floor address must be a fresh index, not a reissue of the authoring run: {floor_addr}"
    );
    funder
        .send(&floor_addr, FUND_ZATOSHIS)
        .await
        .expect("send to the floor-index transparent address");
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the floor-index receive");
    let tip2 = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount after the floor funding")
        .as_u64()
        .expect("height");
    wait_for_balance_at_least(&a18, 2.0, FUND_TIMEOUT).await;
    drop(a18);

    // 11. The from-seed proof: same small gap, same initial_scan - the floor-index receive sits at
    //     index >= initial_scan, so only the gap lookahead past the floor can recover it.
    let mut horizon_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    horizon_cfg.transparent = true;
    horizon_cfg.transparent_gap_limit = Some(SMALL_GAP);
    horizon_cfg.transparent_initial_scan = Some(LARGE_GAP);
    horizon_cfg.restore_mnemonic = Some(AUTHORING_MNEMONIC.to_string());
    horizon_cfg.birthday = Some(pre_fund_height);
    let horizon = Zecd::start(&horizon_cfg)
        .await
        .expect("restore zecd with the same small gap + initial scan (horizon config)");
    horizon
        .wait_until_synced(tip2, FUND_TIMEOUT)
        .await
        .expect("the horizon restore scans to the tip");
    wait_for_balance_at_least(&horizon, 2.0, FUND_TIMEOUT).await;
    let horizon_balance = horizon
        .call("getbalance", json!([]))
        .await
        .expect("getbalance on the horizon instance")
        .as_f64()
        .expect("balance number");
    assert!(
        (horizon_balance - 2.0).abs() < 1e-8,
        "the gap lookahead past the initial_scan floor recovers the floor-index receive \
         (expected 2 ZEC = high-index + floor-index): {horizon_balance}"
    );
    drop(horizon);
    // `zebrad` and `funder` clean up on drop.
}

/// The external child index behind one of the wallet's own transparent addresses, via
/// `getaddressinfo`'s `address_index` extension.
async fn address_index(zecd: &Zecd, addr: &str) -> u64 {
    zecd.call("getaddressinfo", json!([addr]))
        .await
        .expect("getaddressinfo on an own transparent address")["address_index"]
        .as_u64()
        .expect("address_index present for an own transparent address")
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
