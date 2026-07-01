//! Stress regtest: large, note-fragmented wallet - the scaling tier.
//!
//! This reproduces (a scaled version of) the measured finding that a `zecd` send's latency grows
//! with the wallet's note count, and that - with `[spend] pipeline_proving` on - the proof runs
//! **off** the single-writer actor so background sync is no longer frozen for the whole send. See
//! `docs/CONCURRENT_SENDS.md`.
//!
//! It is gated **separately** from the extended tier (`ZECD_REGTEST_STRESS=1`, not
//! `ZECD_REGTEST_EXTENDED`): building thousands of notes and timing multi-minute sends is far too
//! heavy for even the weekly extended run, so the CI workflow drives it only via an explicit
//! dispatch and a rare (monthly) schedule, never on push/PR. The note target is tunable with
//! `ZECD_STRESS_NOTE_COUNT` (default 256) so the same test scales from a quick dispatch smoke to a
//! heavy soak.
//!
//! What it asserts:
//!   1. **Liveness during a send (the Layer-1 fix):** while a large send's proof runs, new blocks
//!      mined on the chain are still *scanned by zecd* before the send returns - i.e. the actor is
//!      not frozen by the proof. With `pipeline_proving` off this would hang (the actor blocks on
//!      `block_in_place` for the whole proof), so this is the discriminating regression guard.
//!   2. **Correctness:** the send still completes and moves funds (it is committed and broadcast).
//!
//! The per-send phase-timing log lines (`send complete (pipelined): N inputs, M orchard actions;
//! select+build … prove+sign … store … broadcast …`) are the Layer-0 profiling artifact - set
//! `ZECD_STDERR=1` to stream them into the CI log.
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN`, `DEVTOOL_BIN` are all set *and*
//! `ZECD_REGTEST_STRESS=1`.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, stress_enabled, stress_note_count, Funder, Lightwalletd, Zebrad, Zecd,
    ZecdConfig,
};

/// Coinbases mined to the funder, then aged past maturity - same single-chain shaping as the
/// funded e2e (see `regtest_funded.rs`); ~21 of these finalize and become spendable.
const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";

/// Value of each note the wallet is fragmented into (0.001 ZEC - comfortably above dust and the
/// ZIP-317 marginal fee, so notes don't decay as the build loop recycles them).
const PER_NOTE_ZAT: u64 = 100_000;
/// Notes created per build round. Each round spends the single large change note (the chunk total
/// is tiny next to it, so the greedy selector covers it with that one note) and fans out into this
/// many small notes, netting ~`BUILD_CHUNK` per round.
const BUILD_CHUNK: usize = 40;
/// Blocks mined per build round so the change note re-confirms before the next round spends it.
const MINE_PER_ROUND: u32 = 4;
/// Blocks mined *while the measured send's proof is in flight*, to prove sync keeps up.
const MINE_DURING_SEND: u32 = 3;

const SYNC_TIMEOUT: Duration = Duration::from_secs(240);
/// Per build-round send (a `BUILD_CHUNK`-output proof; seconds with the cached key).
const BUILD_OP_TIMEOUT: Duration = Duration::from_secs(600);
/// How long zecd has to scan the blocks mined during the measured send. Generous, but far shorter
/// than a large send's proof - so reaching it proves concurrency, not just eventual sync.
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(180);

#[tokio::test]
async fn regtest_stress_many_notes() {
    if !stress_enabled() {
        eprintln!(
            "SKIP regtest_stress_many_notes: set ZECD_REGTEST_STRESS=1 to run the stress tier \
             (see README.md). The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_stress_many_notes: set ZEBRAD_BIN, LIGHTWALLETD_BIN and DEVTOOL_BIN \
             to run the stress e2e (see README.md)."
        );
        return;
    };

    let note_target = stress_note_count();
    eprintln!("stress: building a wallet of >= {note_target} notes");

    // --- Single-chain funding (mirrors regtest_funded.rs) ---
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
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // --- zecd with the pipeline on (and the action cap lifted so big fan-out/sweep sends aren't
    //     rejected by `orchard_action_limit`). cache_proving_key stays default-on: the pipeline
    //     only engages on that cached-Orchard PCZT path. ---
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.pipeline_proving = Some(true);
    cfg.orchard_action_limit = Some(0);
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against regtest zebra");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("address string")
        .to_string();

    // Wait for zecd to be caught up so its mempool stream is open (the build sends appear at
    // 0-conf and the measured send's concurrent sync works off that "new block" signal).
    let tip = zebrad_tip(&zebrad).await;
    zecd.wait_until_synced(tip, SYNC_TIMEOUT)
        .await
        .expect("zecd initial sync");

    // --- Fund zecd with one large note, sized to split into `note_target` notes plus fee/slack. ---
    let headroom = (note_target as u64) * 20_000 + 50_000_000;
    let fund_zat = (note_target as u64) * PER_NOTE_ZAT + headroom;
    funder
        .send(lwd.grpc_port, &zecd_ua, fund_zat)
        .expect("fund zecd with the seed note");
    zebrad.generate_blocks(6).await.expect("confirm the fund");
    let tip = zebrad_tip(&zebrad).await;
    zecd.wait_until_synced(tip, SYNC_TIMEOUT)
        .await
        .expect("zecd sync (funded)");

    // --- Build the fragmented note set: fan out `BUILD_CHUNK` notes per round until we reach the
    //     target. Each round spends the (single, large) change note and creates many small ones. ---
    let build_start = Instant::now();
    let mut notes = confirmed_note_count(&zecd).await;
    let max_rounds = note_target / BUILD_CHUNK + 20;
    let mut round = 0;
    while notes < note_target {
        round += 1;
        assert!(
            round <= max_rounds,
            "note build stalled at {notes}/{note_target} after {round} rounds (insufficient \
             funds, or the selector stopped spending the large change note?)"
        );
        let dest = zecd
            .call("getnewaddress", json!([]))
            .await
            .expect("getnewaddress (fan-out dest)")
            .as_str()
            .expect("address string")
            .to_string();
        let amount = zec_str(PER_NOTE_ZAT);
        let outputs: Vec<_> = (0..BUILD_CHUNK)
            .map(|_| json!({ "address": dest, "amount": amount }))
            .collect();
        // minconf=1 so a change note confirmed this round is immediately spendable next round.
        let opid = zecd
            .call("z_sendmany", json!([zecd_ua, outputs, 1]))
            .await
            .expect("z_sendmany fan-out")
            .as_str()
            .expect("opid string")
            .to_string();
        await_opid(&zecd, &opid, BUILD_OP_TIMEOUT).await;

        zebrad
            .generate_blocks(MINE_PER_ROUND)
            .await
            .expect("confirm fan-out");
        let tip = zebrad_tip(&zebrad).await;
        zecd.wait_until_synced(tip, SYNC_TIMEOUT)
            .await
            .expect("zecd sync (build round)");
        notes = confirmed_note_count(&zecd).await;
        eprintln!("stress: build round {round}: {notes}/{note_target} notes");
    }
    eprintln!(
        "stress: built {notes} notes in {round} rounds ({:?})",
        build_start.elapsed()
    );

    // --- The measured send: sweep a large fraction of the balance back to the funder. A big
    //     fraction forces the greedy selector to pull in many of the small notes → a large Orchard
    //     bundle → a long proof. While that proof runs off the actor, mine blocks and require zecd
    //     to scan them: that is only possible if the actor is NOT frozen by the proof. ---
    let balance = getbalance_zec(&zecd).await;
    let sweep = balance * 0.7;
    assert!(sweep > 0.0, "wallet has no balance to sweep: {balance}");
    eprintln!("stress: measured send sweeps {sweep} ZEC ({notes}-note wallet)");

    let before = zecd.block_count().await.expect("block_count before send");
    let send = zecd.call("sendtoaddress", json!([funder_taddr, sweep]));
    let observe = async {
        // Mine while the proof is in flight; require zecd to scan to the new tip before the send
        // returns. (With pipeline_proving off, the actor would be frozen and this would time out.)
        zebrad
            .generate_blocks(MINE_DURING_SEND)
            .await
            .expect("mine during the measured send");
        let target = before + MINE_DURING_SEND as u64;
        zecd.wait_until_synced(target, OBSERVE_TIMEOUT)
            .await
            .expect(
                "zecd must keep scanning new blocks while a send's proof runs - the actor is \
                 frozen by the proof (pipeline_proving regressed?)",
            );
        target
    };
    let (send_res, synced_to) = tokio::join!(send, observe);
    let txid = send_res.expect("measured sweep send completes");
    let txid = txid.as_str().expect("txid string").to_string();
    eprintln!("stress: send {txid} done; sync kept up to height {synced_to} during the proof");

    // --- Correctness: the swept funds confirm and the balance drops. ---
    zebrad.generate_blocks(6).await.expect("confirm sweep");
    let tip = zebrad_tip(&zebrad).await;
    zecd.wait_until_synced(tip, SYNC_TIMEOUT)
        .await
        .expect("zecd sync (post-sweep)");
    let after = getbalance_zec(&zecd).await;
    assert!(
        after < balance,
        "sweep did not move funds: balance {balance} -> {after}"
    );

    let _ = zecd.call("stop", json!([])).await;
}

/// zebra's current best-block height (the node's own `getblockcount`, independent of zecd's scan).
async fn zebrad_tip(zebrad: &Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount")
        .as_u64()
        .expect("zebra getblockcount number")
}

/// Count zecd's confirmed (minconf=1) notes via `listunspent`.
async fn confirmed_note_count(zecd: &Zecd) -> usize {
    zecd.call("listunspent", json!([1]))
        .await
        .expect("listunspent")
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0)
}

/// zecd's spendable balance in ZEC.
async fn getbalance_zec(zecd: &Zecd) -> f64 {
    let v = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .expect("getbalance number")
}

/// Poll an async operation (`z_sendmany`) to completion, panicking on failure/timeout.
async fn await_opid(zecd: &Zecd, opid: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let st = zecd
            .call("z_getoperationstatus", json!([[opid]]))
            .await
            .expect("z_getoperationstatus");
        let status = st
            .as_array()
            .and_then(|a| a.first())
            .and_then(|o| o.get("status"))
            .and_then(|s| s.as_str())
            .unwrap_or("");
        match status {
            "success" => return,
            "failed" => panic!("operation {opid} failed: {st}"),
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "operation {opid} did not finish within {timeout:?}: {st}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Format zatoshis as an 8-dp ZEC decimal string (for `z_sendmany` amounts).
fn zec_str(zat: u64) -> String {
    format!("{}.{:08}", zat / 100_000_000, zat % 100_000_000)
}
