//! Live failover test: two lightwalletd instances on one zebra chain, zecd configured with
//! `servers = [primary, fallback]`. Kill the primary → zecd fails over to the fallback and
//! keeps following the chain; bring the primary back → prefer-primary re-probing snaps the
//! connection back. Exercises `actor.rs`'s connect-order, reconnect backoff, and
//! `reprobe_primary` - the documented HA feature - against real processes.
//!
//! Skips cleanly when `ZEBRAD_BIN`/`LIGHTWALLETD_BIN` aren't provisioned (see README.md).

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{pick_port, resolve_bin, Lightwalletd, Zebrad, Zecd, ZecdConfig};

const INITIAL_BLOCKS: u32 = 8;
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for a connection transition (failover or snap-back). Generous against
/// the configured 1–2s reconnect backoff and 3s primary re-check.
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(60);

/// Poll `getpeerinfo` until the single peer's `addr` is on `port`. The addr format is
/// `"127.0.0.1:<port> (tls=false)"`, so matching `":<port> "` is unambiguous even when one
/// port number is a substring of the other.
async fn wait_for_peer(zecd: &Zecd, port: u16, what: &str) {
    let needle = format!(":{port} ");
    let deadline = Instant::now() + TRANSITION_TIMEOUT;
    loop {
        let peers = zecd
            .call("getpeerinfo", json!([]))
            .await
            .unwrap_or(json!([]));
        let addr = peers
            .as_array()
            .and_then(|a| a.first())
            .and_then(|p| p["addr"].as_str())
            .unwrap_or("")
            .to_string();
        if addr.contains(&needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: peer did not become *:{port} within {TRANSITION_TIMEOUT:?} (last: {addr:?})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

#[tokio::test]
async fn regtest_failover_prefers_primary() {
    let (Some(zebrad_bin), Some(lwd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_failover_prefers_primary: set ZEBRAD_BIN and LIGHTWALLETD_BIN \
             (see README.md). The harness still compiled and linked."
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial blocks");

    // Two independent lightwalletds indexing the same zebra.
    let lwd1 = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("launch primary lightwalletd");
    let lwd2 = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("launch fallback lightwalletd");
    let primary_port = lwd1.grpc_port;
    let fallback_port = lwd2.grpc_port;

    let mut cfg = ZecdConfig::new(primary_port, pick_port().expect("pick zecd rpc port"));
    cfg.fallback_lightwalletd_port = Some(fallback_port);
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans to the tip");

    // Connected to the primary.
    wait_for_peer(&zecd, primary_port, "initial connection").await;

    // Primary dies → zecd fails over to the fallback and keeps following the chain.
    lwd1.stop();
    zebrad.generate_blocks(3).await.expect("mine during outage");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64 + 3, SYNC_TIMEOUT)
        .await
        .expect("zecd follows the chain through the fallback");
    wait_for_peer(&zecd, fallback_port, "failover to fallback").await;

    // Primary recovers → prefer-primary re-probing snaps back within primary_recheck_secs.
    let _lwd1 = Lightwalletd::start_on(&lwd_bin, zebrad.rpc_port, primary_port)
        .await
        .expect("restart the primary on its original port");
    wait_for_peer(&zecd, primary_port, "snap-back to primary").await;

    // Still live end-to-end on the re-adopted primary.
    zebrad
        .generate_blocks(2)
        .await
        .expect("mine after recovery");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64 + 5, SYNC_TIMEOUT)
        .await
        .expect("zecd follows the chain on the recovered primary");
}
