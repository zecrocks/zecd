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
    extended_enabled, pick_port, resolve_bin, Funder, Zebrad, Zecd, ZecdConfig,
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
/// Blocks live-synced one at a time after the initial batch, so the wallet records
/// note-commitment-tree checkpoints at real scanned heights (the birthday-anchor checkpoint a
/// single-batch sync leaves behind has no `blocks` row and can't be a rewind target). A handful
/// covers the shallow reorg below with margin.
const LIVE_SYNC_BLOCKS: u32 = 5;

#[tokio::test]
async fn regtest_reorg_rewinds_and_follows() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_reorg_rewinds_and_follows: set ZECD_REGTEST_EXTENDED=1 to run the \
             extended tier (see README.md)."
        );
        return;
    }
    let (Some(zebrad_bin), Some(devtool_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("DEVTOOL_BIN"))
    else {
        eprintln!(
            "SKIP regtest_reorg_rewinds_and_follows: set ZEBRAD_BIN and DEVTOOL_BIN \
             (see README.md). The harness still compiled and linked."
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

    // 2. zecd scans the original chain to its tip.
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans the original chain");

    // Seed recent note-commitment-tree checkpoints by live-syncing a few blocks one at a time.
    // A wallet that caught up in a single batch holds only the birthday-anchor checkpoint, which
    // has no `blocks` row and is therefore not a valid `truncate_to_height` rewind target - so a
    // reorg would be unrecoverable. librustzcash writes a checkpoint at each scan batch's start
    // height, so scanning block-by-block records checkpoints at real scanned heights, exactly as
    // a real wallet accrues them from continuous sync. Without this, the rewind below has nothing
    // to rewind to. (The reorg is shallow - it replaces the tip block - so a checkpoint a few
    // blocks back is a valid target.)
    for _ in 0..LIVE_SYNC_BLOCKS {
        let next = zecd.block_count().await.expect("getblockcount") + 1;
        zebrad.generate_blocks(1).await.expect("mine a live block");
        zecd.wait_until_synced(next, SYNC_TIMEOUT)
            .await
            .expect("zecd live-syncs the block (records a checkpoint at a real height)");
    }

    let old_tip = zecd.block_count().await.expect("getblockcount");
    let old_hash_at_tip = zecd
        .call("getblockhash", json!([old_tip]))
        .await
        .expect("getblockhash at the original tip")
        .as_str()
        .expect("hash is a string")
        .to_string();

    // 3. Replace the chain above zebra's finalized height: restart zebra onto a different
    //    miner address so it drops the non-finalized tail and mines a divergent one. zecd
    //    talks straight to zebra, so there is no indexer cache to invalidate.
    zebrad
        .restart_with_miner(&replacement_miner)
        .await
        .expect("restart zebra (drops the non-finalized tail)");
    zebrad
        .generate_blocks(REPLACEMENT_TAIL)
        .await
        .expect("mine the replacement tail");

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

    // The `listsinceblock` cursor survives the reorg: a poller that stored the old tip hash
    // (now reorged away, its `blocks` row deleted by `perform_rewind`) must not wedge on -5.
    // zecd lists from the earliest scanned block and hands back a fresh cursor instead.
    let since_reorged = zecd
        .call("listsinceblock", json!([old_hash_at_tip]))
        .await
        .expect("listsinceblock with a reorged-away cursor must not error");
    assert!(
        since_reorged["transactions"].is_array(),
        "listsinceblock across a reorg returns a transactions list: {since_reorged}"
    );
    assert!(
        since_reorged["lastblock"]
            .as_str()
            .is_some_and(|h| h.len() == 64),
        "listsinceblock across a reorg hands back a fresh 64-hex cursor: {since_reorged}"
    );

    // The wallet survived the rewind: balances and address derivation still answer.
    let bal = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
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
