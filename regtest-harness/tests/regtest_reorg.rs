//! Live reorg test: zecd must follow a chain reorganization through librustzcash's
//! caller-side rewind contract (`perform_rewind` in `sync/engine.rs`), which otherwise has
//! only offline tests. This is the riskiest sync path in the daemon - a mishandled rewind
//! wedges the wallet - so the extended tier exercises it against real processes.
//!
//! The reorg is produced with zebra's own persistence semantics (the same mechanism the
//! funded e2e exploits for coinbase maturity): only blocks deeper than
//! `MAX_BLOCK_REORG_HEIGHT` (99) below the tip are finalized to disk, and a restart resets
//! the tip to the finalized height. So: mine 120 blocks and let zecd scan them, restart
//! zebra (the tip drops to ~21) mining to a *different* coinbase address, and mine a
//! 130-block replacement tail - every block above the finalized height changes (different
//! coinbase output → different hashes; the different address makes that guaranteed rather
//! than timestamp-luck) and the new tip ends higher than the old one. lightwalletd is
//! restarted with a fresh cache on the same port, and zecd must rewind off the orphaned
//! blocks and follow the replacement chain.
//!
//! Extended tier: set `ZECD_REGTEST_EXTENDED=1` (plus ZEBRAD_BIN / LIGHTWALLETD_BIN /
//! DEVTOOL_BIN - devtool only derives the second miner address). Skips cleanly otherwise.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    extended_enabled, pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// The original chain. Must exceed zebra's finality depth (99) so a finalized prefix
/// survives the restart - and so the wallet's birthday (`tip - 100` at init) lands inside it.
const INITIAL_BLOCKS: u32 = 120;
/// The replacement tail mined after the restart. Finalized height (~21) + 130 ends above the
/// old tip (~120), so the replacement chain wins on height as well as on freshness.
const REPLACEMENT_TAIL: u32 = 130;
/// Generous: the rewind walks back through the orphaned range two blocks per truncation
/// retry before the rescan starts.
const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

#[tokio::test]
async fn regtest_reorg_rewinds_and_follows() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_reorg_rewinds_and_follows: set ZECD_REGTEST_EXTENDED=1 to run the \
             extended tier (see README.md)."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_reorg_rewinds_and_follows: set ZEBRAD_BIN, LIGHTWALLETD_BIN and \
             DEVTOOL_BIN (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // A second, distinct coinbase address for the replacement chain (derived offline; the
    // funder wallet itself is never used). Different coinbase output => guaranteed-different
    // replacement blocks.
    let replacement_miner = Funder::derive_transparent_address(&devtool_bin)
        .expect("derive the replacement miner address");

    // 1. The original chain: zebra mining to the default throwaway address.
    let mut zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine the original chain");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("launch lightwalletd");

    // 2. zecd scans the original chain to its tip.
    let cfg = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans the original chain");
    let old_tip = zecd.block_count().await.expect("getblockcount");
    let old_hash_at_tip = zecd
        .call("getblockhash", json!([old_tip]))
        .await
        .expect("getblockhash at the original tip")
        .as_str()
        .expect("hash is a string")
        .to_string();

    // 3. Replace the chain above zebra's finalized height. Stop lightwalletd first so its
    //    cache can never serve stale blocks; a fresh instance re-ingests the new chain.
    let lwd_port = lwd.grpc_port;
    lwd.stop();
    zebrad
        .restart_with_miner(&replacement_miner)
        .await
        .expect("restart zebra (drops the non-finalized tail)");
    zebrad
        .generate_blocks(REPLACEMENT_TAIL)
        .await
        .expect("mine the replacement tail");
    let _lwd = Lightwalletd::start_on(&lwd_bin, zebrad.rpc_port, lwd_port)
        .await
        .expect("restart lightwalletd on the same port");

    // 4. zecd reconnects, hits the prev-hash mismatch above the finalized height, rewinds
    //    (perform_rewind), and rescans to the replacement tip - which is above the old one.
    zecd.wait_until_synced(old_tip + 1, SYNC_TIMEOUT)
        .await
        .expect("zecd rewinds and follows the replacement chain past the old tip");

    // The block at the old tip height was replaced.
    let new_hash_at_old_tip = zecd
        .call("getblockhash", json!([old_tip]))
        .await
        .expect("getblockhash after the reorg")
        .as_str()
        .expect("hash is a string")
        .to_string();
    assert_ne!(
        new_hash_at_old_tip, old_hash_at_tip,
        "the block at height {old_tip} must have been replaced by the reorg"
    );

    // zecd converges on zebra's view of the new best block.
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        let zebra_best = zebrad
            .rpc("getbestblockhash", json!([]))
            .await
            .expect("zebra getbestblockhash");
        let zecd_best = zecd
            .call("getbestblockhash", json!([]))
            .await
            .expect("zecd getbestblockhash");
        if zecd_best == zebra_best {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never converged on zebra's best block: {zecd_best} != {zebra_best}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // The wallet survived the rewind: balances and address derivation still answer.
    let bal = zecd.call("getbalance", json!([])).await.expect("getbalance");
    assert_eq!(bal.as_f64(), Some(0.0), "the empty wallet is still empty");
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress after the reorg");
    assert!(
        addr.as_str().is_some_and(|a| a.starts_with("uregtest1")),
        "address derivation still works: {addr}"
    );
}
