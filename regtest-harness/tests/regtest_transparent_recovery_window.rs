//! Transparent **recovery-window** policy end-to-end: prove the two `getnewaddress` behaviours at
//! the edge of the stateless-restore recovery window (the `transparent_gap_limit` /
//! `transparent_initial_scan` span):
//!
//!   * `transparent_allow_beyond_recovery_window = false` (fail closed): once the gap limit is
//!     reached, `getnewaddress "" "transparent"` returns an actionable `-4` error rather than
//!     issuing an address that a from-seed restore could not recover; and
//!   * the default (`= true`, warn-only): the **same** small gap keeps issuing past the limit,
//!     handing out distinct sequential t-addresses (each logged as outside the window).
//!
//! No funding/restore is needed - this exercises the address-generation policy directly, so it
//! needs only zebrad (for a chain tip) and zecd. Standard tier: it's the guard for the
//! recovery-window hard-stop and the beyond-gap issuance path.
//!
//! Skips cleanly unless `ZEBRAD_BIN` is set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{pick_port, resolve_bin, RpcError, Zebrad, Zecd, ZecdConfig};

const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const READY_TIMEOUT: Duration = Duration::from_secs(120);
/// Small gap so the window is reached after only a few addresses (CI speed). The mechanism is
/// identical at the default of 20.
const SMALL_GAP: u32 = 3;
/// Extra addresses to hand out past the gap on the allow-beyond wallet.
const BEYOND: u32 = 3;

#[tokio::test]
async fn regtest_transparent_recovery_window_hard_stop_and_allow_beyond() {
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_transparent_recovery_window_hard_stop_and_allow_beyond: set ZEBRAD_BIN \
             to run the transparent recovery-window e2e (see README.md)."
        );
        return;
    };

    // A minimal chain so zecd has a tip to sync to and can serve getnewaddress.
    let zebrad = Zebrad::start_with_miner(&zebrad_bin, TAIL_MINER_ADDRESS)
        .await
        .expect("start zebrad");
    zebrad
        .generate_blocks(10)
        .await
        .expect("mine a short regtest chain");

    // --- Wallet A: fail closed past the recovery window. ---
    let mut closed_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    closed_cfg.transparent = true;
    closed_cfg.transparent_gap_limit = Some(SMALL_GAP);
    closed_cfg.transparent_allow_beyond_recovery_window = Some(false);
    let closed = Zecd::start(&closed_cfg)
        .await
        .expect("start the fail-closed zecd");
    wait_for_ready(&closed, READY_TIMEOUT).await;

    // The account's default address already consumes part of the external window (index 0), so the
    // exact number of in-window addresses `getnewaddress` can hand out is the gap limit minus what
    // the account has already exposed. Rather than hard-code that count, keep issuing until the
    // recovery window fills: at least one address must succeed, and within `gap_limit` calls the
    // wallet must fail closed with the actionable -4 error (it never issues beyond the window when
    // allow_beyond = false).
    let mut issued = 0u32;
    let mut wall = None;
    for _ in 0..=SMALL_GAP {
        match new_transparent(&closed).await {
            Ok(a) => {
                assert!(a.starts_with("tm"), "bare t-addr expected, got {a}");
                issued += 1;
            }
            Err(e) => {
                wall = Some(e);
                break;
            }
        }
    }
    assert!(
        issued >= 1,
        "at least one in-window transparent address must be issued before the wall"
    );
    let err = wall.expect(
        "getnewaddress past the gap must fail closed within the gap limit when allow_beyond = false",
    );
    match err {
        RpcError::Rpc { code, message } => {
            assert_eq!(
                code, -4,
                "Bitcoin Core RPC_WALLET_ERROR for a wallet-policy refusal"
            );
            assert!(
                message.contains("gap limit")
                    && message.contains("transparent_allow_beyond_recovery_window"),
                "the error names the cause and the opt-out knob: {message}"
            );
        }
        other => panic!("expected an RPC error, got {other}"),
    }
    drop(closed);

    // --- Wallet B: default (allow beyond, warn-only) keeps issuing. ---
    let mut open_cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick rpc port"));
    open_cfg.transparent = true;
    open_cfg.transparent_gap_limit = Some(SMALL_GAP);
    // transparent_allow_beyond_recovery_window left at its default (true).
    let open = Zecd::start(&open_cfg)
        .await
        .expect("start the allow-beyond zecd");
    wait_for_ready(&open, READY_TIMEOUT).await;

    let mut addrs = Vec::new();
    for i in 0..(SMALL_GAP + BEYOND) {
        let a = new_transparent(&open)
            .await
            .unwrap_or_else(|e| panic!("getnewaddress #{i} must succeed with allow_beyond: {e}"));
        assert!(a.starts_with("tm"), "bare t-addr expected, got {a}");
        addrs.push(a);
    }
    let distinct: std::collections::HashSet<&String> = addrs.iter().collect();
    assert_eq!(
        distinct.len(),
        (SMALL_GAP + BEYOND) as usize,
        "each getnewaddress (in and beyond the window) returns a distinct sequential t-addr: {addrs:?}"
    );

    drop(open);
    // `zebrad` cleans up on drop.
}

/// `getnewaddress "" "transparent"`, returning the bare t-address string.
async fn new_transparent(zecd: &Zecd) -> Result<String, RpcError> {
    let v = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await?;
    Ok(v.as_str().expect("address string").to_string())
}

/// Block until zecd reports its upstream peer `ready` (caught up; a chain tip is known so
/// `getnewaddress` can derive within the gap).
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
            return;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never reached ready: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
