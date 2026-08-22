//! Live reorg test: zecd must follow a chain reorganization through librustzcash's
//! caller-side rewind contract (`perform_rewind` in `sync/engine.rs`), which otherwise has
//! only offline tests. This is the riskiest sync path in the daemon - a mishandled rewind
//! wedges the wallet - so the extended tier exercises it against real processes.
//!
//! The reorg is produced deterministically: mine 120 blocks and let zecd scan them, restart
//! zebra onto a *different* coinbase address, invalidate the old tip block, and mine a
//! 130-block replacement tail. The different miner address is what makes the replacement
//! blocks guaranteed to differ rather than timestamp-luck; `invalidateblock` is what makes
//! the divergence happen at all. zecd must rewind off the orphaned block and follow the
//! replacement chain, which ends far above the old tip.
//!
//! The reorg is deliberately SHALLOW (one block). A rewind target has to be a checkpoint with
//! a real `blocks` row, which is why the test seeds recent checkpoints below; a reorg deeper
//! than those exercises `perform_rewind`'s two-blocks-per-pass retry walk instead, which is a
//! different and much slower path.
//!
//! NB an earlier version relied on the restart alone dropping the non-finalized tail. Zebra
//! backs those blocks up and restores them, so that only ever worked when the backup task had
//! not yet flushed the tip block: the test passed or failed on that race.
//!
//! Extended tier: set `ZECD_REGTEST_EXTENDED=1` (plus ZEBRAD_BIN). Skips cleanly otherwise.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    extended_enabled, pick_port, resolve_node_bin, RegtestNode, Zebrad, Zecd, ZecdConfig,
    ALT_MINER_ADDRESS,
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
             extended tier."
        );
        return;
    }
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_reorg_rewinds_and_follows: set {}. The harness still compiled and \
             linked.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    // A second coinbase address for the replacement chain, distinct from the one `Zebrad::start`
    // mines to. Different coinbase output => guaranteed-different replacement blocks. No wallet
    // needs to control it - the test only cares that the blocks differ.
    let replacement_miner = ALT_MINER_ADDRESS;

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

    // 3. Replace the chain above the old tip: restart zebra onto a different miner address so
    //    the replacement blocks are guaranteed to differ (different coinbase output), then
    //    force the divergence explicitly. zecd talks straight to zebra, so there is no indexer
    //    cache to invalidate.
    zebrad
        .restart_with_miner(replacement_miner)
        .await
        .expect("restart zebra onto the replacement miner address");

    // The restart alone does NOT reliably drop the tail. Zebra backs its non-finalized blocks
    // up and restores them on startup, so whether the tip block survives depends on whether the
    // backup task had flushed it before shutdown - a race this test used to rely on losing.
    // When the backup wins, the chain comes back whole, no reorg happens, and the assertion
    // below fails on a chain that was never reorganized. Invalidate the old tip explicitly
    // instead, which drops exactly one block whatever the backup did.
    let restored_tip_hash = zebrad
        .rpc("getblockhash", json!([old_tip]))
        .await
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    if restored_tip_hash.as_deref() == Some(old_hash_at_tip.as_str()) {
        zebrad
            .rpc("invalidateblock", json!([old_hash_at_tip]))
            .await
            .expect("invalidate the old tip block (zebra restored it from its backup)");
    }

    // Pin the mechanism, not just its effect. Everything below asserts on a chain that has
    // already been rebuilt, so if the divergence never happens the failure surfaces 130 blocks
    // later as a hash comparing equal to itself - which is how the backup race read for weeks.
    // Assert here, where the cause is, that the chain really is shorter than the tip zecd
    // scanned.
    let diverged_height = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount after the invalidation")
        .as_u64()
        .expect("a height");
    assert!(
        diverged_height < old_tip,
        "the chain must diverge below the old tip {old_tip} before the replacement tail is \
         mined, but zebra is still at {diverged_height}"
    );

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
