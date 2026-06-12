//! Hang-class fault test: a lightwalletd that *stops responding without dying* (SIGSTOP).
//!
//! The kernel keeps a stopped process's sockets alive - TCP connects succeed and segments
//! are ACKed - so neither a dead-peer error nor a dial timeout ever fires. The only things
//! that can notice are the HTTP/2 keepalive on the channel and the actor's per-RPC
//! deadlines; this is the regression test for those two layers. Three contracts:
//!
//! 1. the actor's command loop stays live (an RPC that round-trips through it answers
//!    within a bounded time, even while the sync path is parked on a hung call);
//! 2. the hang is *detected* (the peer list empties although the process never died);
//! 3. the daemon recovers on its own once the upstream resumes.
//!
//! Skips cleanly when `ZEBRAD_BIN`/`LIGHTWALLETD_BIN` aren't provisioned (see README.md).

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{pick_port, resolve_bin, Lightwalletd, Zebrad, Zecd, ZecdConfig};

const INITIAL_BLOCKS: u32 = 8;
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
/// Worst-case time for the actor to notice the hang and free its loop: one per-RPC deadline
/// (≤30s) or the HTTP/2 keepalive (15s interval + 5s timeout), plus generous slack for a
/// reconnect attempt that itself parks on the stopped-but-accepting socket.
const DETECT_TIMEOUT: Duration = Duration::from_secs(90);

#[tokio::test]
async fn regtest_hung_upstream_detected_and_recovered() {
    let (Some(zebrad_bin), Some(lwd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_hung_upstream_detected_and_recovered: set ZEBRAD_BIN and \
             LIGHTWALLETD_BIN (see README.md). The harness still compiled and linked."
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial blocks");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("launch lightwalletd");

    let cfg = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans to the tip");
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let addr = addr.as_str().expect("address is a string").to_string();

    // Hang - don't kill - the upstream, and keep mining: zebra is unaffected, and the
    // stopped lightwalletd's sockets stay open underneath zecd's live channel.
    lwd.pause().expect("SIGSTOP lightwalletd");
    zebrad.generate_blocks(3).await.expect("mine while hung");

    // 1. The actor's command loop must not wedge behind the hung sync path. A send
    //    round-trips through the actor and fails on funds *before* touching the network,
    //    so it measures pure command-loop latency. Without the per-RPC deadlines and
    //    keepalive this call parks forever.
    let t0 = Instant::now();
    let err = tokio::time::timeout(
        DETECT_TIMEOUT,
        zecd.call("sendtoaddress", json!([addr, 1.0])),
    )
    .await
    .expect("the actor command loop must answer while the upstream hangs")
    .expect_err("the empty wallet cannot fund the probe send");
    assert_eq!(
        err.code(),
        Some(-6),
        "the probe send fails on funds, not on a wedged actor: {err}"
    );
    eprintln!(
        "actor answered a command in {:?} with the upstream hung",
        t0.elapsed()
    );

    // 2. The hang is detected: the channel dies by keepalive/deadline and the peer list
    //    empties, although the process never exited and its socket still accepts.
    let deadline = Instant::now() + DETECT_TIMEOUT;
    loop {
        let peers = zecd
            .call("getpeerinfo", json!([]))
            .await
            .expect("getpeerinfo");
        if peers.as_array().is_some_and(|a| a.is_empty()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the hung upstream was never detected: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 3. Recovery is automatic: resume the process and zecd reconnects, then scans the
    //    blocks mined during the hang.
    lwd.resume().expect("SIGCONT lightwalletd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64 + 3, SYNC_TIMEOUT)
        .await
        .expect("zecd recovers and follows the chain after the upstream resumes");
}
