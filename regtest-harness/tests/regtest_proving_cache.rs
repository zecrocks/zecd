//! Proving-key-cache benchmark + equivalence (regtest, real Orchard proving).
//!
//! Validates the `[spend] cache_proving_key` knob end-to-end on a real funded wallet, and
//! measures its effect. Both paths produce real, broadcastable, mineable Orchard sends:
//!
//!   * **cache ON** (default): sends prove via the PCZT roles with the Orchard proving key
//!     built once at startup and reused.
//!   * **cache OFF**: sends prove via the fused `create_proposed_transactions`, which rebuilds
//!     the Orchard proving key (`ProvingKey::build()`, a full keygen) on *every* transaction.
//!
//! The wallet is funded once; the same daemon is then restarted with the cache flipped, so the
//! two paths run against the same wallet and funds. Every send on both paths is asserted to mine
//! and confirm - this is the **both-paths correctness gate** (it caught a real PCZT signing bug).
//! Each `sendtoaddress` is also timed and the timings printed, but they are *not* asserted on:
//! shared-runner proving + actor-sync noise swamps the keygen delta across a couple of sends, so
//! the precise saving is measured by the controlled microbench instead.
//!
//! Skips cleanly unless `ZEBRAD_BIN` and `ZALLET_BIN` are set.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{
    pick_port, resolve_bin, resolve_node_bin, start_funder, DEFAULT_MINER_ADDRESS, FOREIGN_TADDR,
    regtest_nuparams, Zebrad, Zecd, ZecdConfig,
};

/// See `regtest_funded.rs` for the coinbase-maturity dance these encode.
const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
/// Fund the wallet generously (5 ZEC) so it can do several sends without running dry.
const FUND_ZATOSHIS: u64 = 500_000_000;
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
/// Sends per path. Two exercises each path more than once while keeping the test bounded; the
/// timing is informational (not asserted), so a small count is fine.
const SENDS_PER_PATH: u32 = 2;
/// Amount per send, in ZEC (well under the funded total even across all sends + fees).
const SEND_AMOUNT_ZEC: f64 = 0.1;

/// zebrad's current best height (the harness mines via `generate`; this reads the tip back).
async fn tip(zebrad: &Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebrad getblockcount")
        .as_u64()
        .expect("getblockcount height")
}

/// Run `n` real `sendtoaddress` calls back to `to_ua`, timing each (the call blocks through
/// proving), confirming between sends so the change becomes spendable again, and asserting each
/// send mined. Returns the per-send latencies.
async fn timed_sends(zecd: &Zecd, zebrad: &Zebrad, to_ua: &str, n: u32) -> Vec<Duration> {
    let mut times = Vec::new();
    for i in 0..n {
        let start = Instant::now();
        let txid: Value = zecd
            .call("sendtoaddress", json!([to_ua, SEND_AMOUNT_ZEC]))
            .await
            .unwrap_or_else(|e| panic!("sendtoaddress #{i} failed: {e}"));
        times.push(start.elapsed());
        let txid = txid.as_str().expect("txid string").to_string();

        // Confirm the send so its change clears the trusted-confirmation depth before the next.
        let target = tip(zebrad).await + 5;
        zebrad
            .generate_blocks(5)
            .await
            .expect("mine to confirm a send");
        zecd.wait_until_synced(target, FUND_TIMEOUT)
            .await
            .expect("zecd sync after a send");

        // Coverage: the send is a valid, mined transaction (both paths must produce this).
        let gt = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction on our send");
        let confs = gt
            .get("confirmations")
            .and_then(|c| c.as_i64())
            .unwrap_or(0);
        assert!(
            confs >= 1,
            "send {txid} did not confirm (confs={confs}): {gt}"
        );
    }
    times
}

#[tokio::test]
async fn regtest_proving_key_cache_benchmark() {
    let (Some(zebrad_bin), Some(zallet_bin)) = (
        resolve_node_bin(),
        resolve_bin("ZALLET_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_proving_key_cache_benchmark: set the node binary env var (ZEBRAD_BIN or ZAKURAD_BIN) and ZALLET_BIN to \
             run it (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // --- Fund a zecd wallet (mine shielded coinbase to the zallet funder, then send to zecd). ---
    let zebrad = Zebrad::start(&zebrad_bin).await.expect("start zebrad");
    zebrad.bootstrap_zallet().await.expect("bootstrap Zallet sync");
    let funder = start_funder(
        &zallet_bin,
        zebrad.rpc_port,
        pick_port().expect("pick zallet rpc port"),
        &regtest_nuparams(false),
    )
    .await
    .expect("start zallet funder");
    zebrad
        .generatetoaddress(FUNDER_COINBASES, &funder.ua)
        .await
        .expect("mine shielded coinbase to funder");
    zebrad
        .generatetoaddress(MATURITY_TAIL, DEFAULT_MINER_ADDRESS)
        .await
        .expect("mine maturity tail");
    funder
        .rpc
        .wait_for_account_balance(&funder.account_uuid, FUND_ZATOSHIS, Duration::from_secs(120))
        .await
        .expect("wait for funder to see shielded coinbase");
    let _funder_taddr = FOREIGN_TADDR.to_string();
    let funder_ua = funder.ua.clone();

    // --- Start zecd with the cache ON (explicit), fund it, wait until it sees the funds. ---
    // zecd is zebra-only (talks straight to zebrad); the zallet funder also talks straight to
    // zebrad via its in-process zaino indexer.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.cache_proving_key = Some(true);
    let mut zecd = Zecd::start(&cfg).await.expect("start zecd (cache on)");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("address string")
        .to_string();
    funder.rpc
        .z_sendmany_and_wait(&funder.ua, &zecd_ua, FUND_ZATOSHIS, None)
        .await
        .expect("fund zecd");
    let target = tip(&zebrad).await + 12;
    zebrad.generate_blocks(12).await.expect("confirm funding");
    zecd.wait_until_synced(target, FUND_TIMEOUT)
        .await
        .expect("zecd sync to the funded tip");

    // --- Benchmark: time sends with the cache ON, then restart with it OFF and repeat. ---
    let on_times = timed_sends(&zecd, &zebrad, &funder_ua, SENDS_PER_PATH).await;

    cfg.cache_proving_key = Some(false);
    zecd.restart(&cfg)
        .await
        .expect("restart zecd with cache off");
    zecd.wait_until_synced(tip(&zebrad).await, FUND_TIMEOUT)
        .await
        .expect("zecd resync after restart");
    let off_times = timed_sends(&zecd, &zebrad, &funder_ua, SENDS_PER_PATH).await;

    // --- Report the timings (informational). ---
    //
    // This is the both-paths *correctness* gate: the assertions that matter ran inside
    // `timed_sends` (every send on both the PCZT-cached and fused paths mined and confirmed).
    // The timings below are printed for the record but NOT asserted on: a shared CI runner's
    // per-send latency is dominated by Orchard proving (tens of seconds) and actor sync
    // contention, with several seconds of run-to-run variance, so across only a couple of sends
    // the keygen delta the cache removes is swamped by noise. The precise, isolated keygen cost
    // is measured by the controlled microbenchmark. (Empirically the cache path is at-worst-equal: it does strictly
    // less work - the proof is identical and the keygen is skipped - so it can never be slower.)
    let on_total: Duration = on_times.iter().sum();
    let off_total: Duration = off_times.iter().sum();
    let on_avg = on_total / SENDS_PER_PATH;
    let off_avg = off_total / SENDS_PER_PATH;

    println!("\n================ proving-key cache benchmark ({SENDS_PER_PATH} sends/path) ================");
    println!("cache ON  (PCZT, cached key):    per-send {on_times:?}  avg {on_avg:?}");
    println!("cache OFF (fused, rebuilds key):  per-send {off_times:?}  avg {off_avg:?}");
    println!(
        "(timings are indicative only - shared-runner proving noise dominates; see the microbench)"
    );
    println!(
        "=====================================================================================\n"
    );

    zecd.shutdown().await.expect("zecd graceful shutdown");
}
