//! Regression guard for the **responsiveness** half of the transparent initial-sync work.
//!
//! #81 made the `transparent_initial_scan` pre-exposure *incremental* (one chunk per actor pass,
//! with a pollable `getwalletinfo.transparent.initial_sync` progress surface) - but the chunking
//! only sliced the work up; it still ran each chunk *synchronously* on the actor's runtime worker
//! with no `block_in_place` and no runtime yield between chunks. So the actor task never suspended
//! during the (multi-minute, for a deep scan) window, and read RPCs - which are supposed to bypass
//! the actor on their own short-lived SQLite connections - stalled for the whole time. The progress
//! reporting shipped; "non-blocking" did not.
//!
//! Nothing asserted the daemon stayed live during the window, so the regression was invisible. This
//! test is that assertion: it starts a wallet with a deep `transparent_initial_scan`, then hammers
//! read RPCs every ~250 ms throughout pre-exposure and fails if any read blocks longer than
//! [`MAX_READ_LATENCY`]. It probes two read paths deliberately:
//!   * `getblockcount` - a pure `watch`-channel read (no DB), so it isolates async-runtime worker
//!     starvation (the part `block_in_place` + the chunk-boundary yield fix); and
//!   * `getwalletinfo` - a short-lived SQLite read connection, so it also covers the DB/WAL
//!     contention the per-chunk single transaction (`transactionally`) was added to avoid.
//!
//! With the bug present, every probe during the ~tens-of-seconds window blocks far past the bound
//! (the original report measured a full ~3-minute outage), so the test fails on the first stalled
//! read. With the fix, reads stay sub-second throughout.
//!
//! Only needs `ZEBRAD_BIN` (no lightwalletd/funder - there's nothing to fund; we only watch the
//! pre-exposure window). Skips cleanly if it's unset.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{pick_port, resolve_bin, Zebrad, Zecd, ZecdConfig};

/// Deep enough that pre-exposure takes well over ten seconds on CI hardware (derivation is
/// CPU-bound at ~1k addr/s), giving dozens of probe ticks inside the window - but not so deep the
/// test drags. Sized purely for an observable window, not to mirror an exchange's real depth.
const TRANSPARENT_INITIAL_SCAN: u32 = 50_000;

/// The responsiveness bound. A healthy read of either kind returns in milliseconds; the regression
/// blocks reads for the *entire* pre-exposure window (tens of seconds to minutes), so any threshold
/// well under that catches it. 3 s is generous headroom over the normal sub-second case for noisy
/// CI while still flagging a daemon that has gone dark.
const MAX_READ_LATENCY: Duration = Duration::from_secs(3);

/// Require this many probe ticks observed *while pre-exposure was in progress*, so a vacuous pass
/// (window finished before we looked) can't masquerade as success. The window is tens of seconds at
/// ~250 ms/tick, so this is reached with large margin; if a future speedup shrinks the window below
/// it, raise `TRANSPARENT_INITIAL_SCAN` rather than lowering this.
const MIN_IN_PROGRESS_TICKS: u32 = 5;

/// Overall cap on how long pre-exposure may take before we give up (it must *complete*, proving the
/// chunk loop converges, not just stay responsive).
const PREEXPOSE_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_transparent_preexpose_stays_responsive() {
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_transparent_preexpose_stays_responsive: set ZEBRAD_BIN to run the \
             transparent pre-exposure responsiveness e2e (see README.md)."
        );
        return;
    };

    // A bare regtest zebrad with a small chain is all we need - pre-exposure runs on the actor at
    // startup, before/around the (trivial) block scan, independent of any funds.
    let zebrad = Zebrad::start(&zebrad_bin)
        .await
        .expect("start regtest zebrad");
    zebrad
        .generate_blocks(10)
        .await
        .expect("mine a small chain so there is a tip");

    // Transparent receiving on, with a deep initial scan so pre-exposure is a long, observable
    // window. No restore: a fresh init's account exists immediately, so the actor begins
    // pre-exposing as soon as it connects.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.transparent = true;
    cfg.transparent_initial_scan = Some(TRANSPARENT_INITIAL_SCAN);
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with a deep transparent initial scan");

    // Probe reads continuously until pre-exposure reports complete. Every probe is bounded by
    // `MAX_READ_LATENCY` (via a hard client-side timeout, so a blocked daemon fails the test in
    // seconds instead of hanging for minutes). Track the in-progress ticks to prove we actually
    // watched the window, and the worst latency for the final message.
    let deadline = Instant::now() + PREEXPOSE_TIMEOUT;
    let mut in_progress_ticks = 0u32;
    let mut max_latency = Duration::ZERO;

    loop {
        // `getwalletinfo` is itself a DB-read probe *and* carries the progress surface.
        let (info, wi_latency) = timed_read(&zecd, "getwalletinfo", json!([])).await;
        max_latency = max_latency.max(wi_latency);

        // A pure watch-channel read: isolates runtime-scheduler starvation from DB contention.
        let (_blocks, bc_latency) = timed_read(&zecd, "getblockcount", json!([])).await;
        max_latency = max_latency.max(bc_latency);

        let initial = &info["transparent"]["initial_sync"];
        if initial.is_object() {
            if initial["complete"].as_bool().unwrap_or(false) {
                break;
            }
            in_progress_ticks += 1;
        }

        assert!(
            Instant::now() < deadline,
            "transparent pre-exposure did not complete within {PREEXPOSE_TIMEOUT:?} \
             (in-progress ticks: {in_progress_ticks}); the chunk loop may not be converging"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    assert!(
        in_progress_ticks >= MIN_IN_PROGRESS_TICKS,
        "only observed {in_progress_ticks} in-progress tick(s) (< {MIN_IN_PROGRESS_TICKS}): the \
         pre-exposure window was too short to be a meaningful responsiveness probe - raise \
         TRANSPARENT_INITIAL_SCAN"
    );
    eprintln!(
        "transparent pre-exposure stayed responsive: {in_progress_ticks} in-progress probe ticks, \
         worst read latency {max_latency:?} (bound {MAX_READ_LATENCY:?})"
    );

    drop(zecd);
    // `zebrad` cleans up on drop.
}

/// Issue one read RPC, enforcing [`MAX_READ_LATENCY`] with a hard timeout. Panics with an
/// actionable message if the call blocks past the bound (the regression) or errors. Returns the
/// decoded result and the measured latency.
async fn timed_read(zecd: &Zecd, method: &str, params: Value) -> (Value, Duration) {
    let start = Instant::now();
    match tokio::time::timeout(MAX_READ_LATENCY, zecd.call(method, params)).await {
        Err(_) => panic!(
            "{method} did not return within {MAX_READ_LATENCY:?} during transparent pre-exposure: \
             the daemon is blocked on the single-writer actor's initial-scan derivation. Read RPCs \
             must bypass the actor and stay live (block_in_place + a runtime yield between chunks)."
        ),
        Ok(Err(e)) => panic!("{method} failed during transparent pre-exposure: {e}"),
        Ok(Ok(v)) => (v, start.elapsed()),
    }
}
