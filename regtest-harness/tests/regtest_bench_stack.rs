//! TEMPORARY benchmark: the librustzcash stack vs the Zakura Common stack, end to end.
//!
//! Runs the same wallet workload against two (or more) `zecd` binaries on ONE regtest chain
//! funded by ONE pinned funder, alternating binaries across rounds so machine drift cannot favour
//! whichever ran last. Every measurement is the wall clock a user or operator actually
//! experiences on the daemon:
//!
//! * `send` - `sendtoaddress` latency (inline proving, so the RPC blocks through select+build,
//!   prove+sign, store, broadcast). Amounts are chosen so the input count grows across the
//!   sends (1, 1, 2, 3, ... notes).
//! * `fanout` - a `z_sendmany` paying N of the wallet's own addresses in one transaction (the
//!   exchange batch-payout shape; ~N Orchard actions).
//! * `restore` - a from-seed restore of the same wallet: time from RPC-up to fully scanned at
//!   the tip (trial decryption + note commitment tree work over the whole regtest chain, plus
//!   the wallet's background keygen competing for cores).
//! * `keygen` - read from the daemon log (`ZECD_STDERR=1`): the background Orchard + Ironwood
//!   proving-key build.
//!
//! With `ZECD_STDERR=1 RUST_LOG=zecd=info` the daemon's `send complete` lines (with
//! `prove_ms`, `build_ms`, ...) land in the test output, tagged by RPC port; the test prints a
//! `BENCH port=<port> label=<label>` line per daemon so a post-processor can attribute them.
//!
//! Configuration (all env):
//!   ZECD_BENCH_BINS   = "label=/path/to/zecd,label2=/path/to/zecd2"  (required)
//!   ZECD_BENCH_ROUNDS = rounds per binary (default 2)
//!   ZECD_BENCH_SENDS  = sends per round (default 5)
//!   ZECD_BENCH_FANOUT = outputs in the fan-out send (default 16; 0 disables)
//!   ZEBRAD_BIN, ZECD_FUNDER_BIN as for every regtest.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{
    pick_port, resolve_node_bin, start_funded_chain, zec_str, Zebrad, Zecd, ZecdConfig,
};

const NOTE_ZAT: u64 = 50_000_000; // 0.5 ZEC per funded note
/// Enough notes that the growing-input sends (1+1+2+3+4 = 11 notes' worth) stay funded.
const NOTES: usize = 14;
/// Received (untrusted) notes need ZIP-315's 10 confirmations before they are spendable.
const FUND_CONFS: u32 = 10;
const SYNC_TIMEOUT: Duration = Duration::from_secs(300);

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn tip(zebrad: &Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("height")
}

/// Mine `n` blocks and wait for `zecd` to scan them; returns the scan latency (from the mine
/// returning to the daemon reporting the new tip).
async fn mine_and_sync(zebrad: &Zebrad, zecd: &Zecd, n: u32) -> Duration {
    let target = tip(zebrad).await + n as u64;
    zebrad.generate_blocks(n).await.expect("mine");
    let t = Instant::now();
    zecd.wait_until_synced(target, SYNC_TIMEOUT)
        .await
        .expect("sync");
    t.elapsed()
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

#[tokio::test]
async fn regtest_bench_stack() {
    let Some(bins_spec) = std::env::var("ZECD_BENCH_BINS").ok() else {
        eprintln!("SKIP regtest_bench_stack: set ZECD_BENCH_BINS=label=path,label=path");
        return;
    };
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!("SKIP regtest_bench_stack: set ZEBRAD_BIN");
        return;
    };
    let bins: Vec<(String, String)> = bins_spec
        .split(',')
        .map(|kv| {
            let (k, v) = kv.split_once('=').expect("label=path");
            (k.to_string(), v.to_string())
        })
        .collect();
    let rounds = env_usize("ZECD_BENCH_ROUNDS", 2);
    let sends = env_usize("ZECD_BENCH_SENDS", 5);
    let fanout = env_usize("ZECD_BENCH_FANOUT", 16);

    let (zebrad, funder) = start_funded_chain(&zebrad_bin).await.expect("funded chain");
    let funder_ua = funder.unified_address().to_string();
    eprintln!("BENCH chain ready at height {}", tip(&zebrad).await);

    let mut results: Vec<Value> = Vec::new();

    for round in 0..rounds {
        // Alternate the order each round so drift (thermal, page cache, chain height) is
        // shared rather than attributed to one stack.
        let order: Vec<&(String, String)> = if round % 2 == 0 {
            bins.iter().collect()
        } else {
            bins.iter().rev().collect()
        };
        for (label, bin) in order {
            std::env::set_var("ZECD_BIN", bin);
            let version = std::process::Command::new(bin)
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();

            let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("port"));
            cfg.pipeline_proving = Some(false);
            cfg.orchard_action_limit = Some(0);
            let t0 = Instant::now();
            let zecd = Zecd::start(&cfg).await.expect("start zecd");
            let startup_ms = ms(t0.elapsed());
            eprintln!(
                "BENCH port={} label={} round={} version={:?}",
                cfg.rpc_port, label, round, version
            );
            let chain_tip = tip(&zebrad).await;
            zecd.wait_until_synced(chain_tip, SYNC_TIMEOUT)
                .await
                .expect("initial sync");

            // Fund with NOTES equal notes so input counts are predictable.
            let mut addrs = Vec::new();
            for _ in 0..NOTES {
                let a = zecd
                    .call("getnewaddress", json!([]))
                    .await
                    .expect("getnewaddress");
                addrs.push(a.as_str().unwrap().to_string());
            }
            let outputs: Vec<(String, u64)> = addrs.iter().map(|a| (a.clone(), NOTE_ZAT)).collect();
            funder.send_many(&outputs).await.expect("fund");
            let fund_scan_ms = ms(mine_and_sync(&zebrad, &zecd, FUND_CONFS).await);

            // Sends with growing input counts: 0.4 (1 note), 0.4 (1), 0.9 (2), 1.4 (3), 1.9 (4), ...
            // Each is paid back to the funder; change returns as a fresh note.
            let mut send_ms = Vec::new();
            for i in 0..sends {
                let inputs = if i < 2 { 1 } else { i };
                let amount_zat = (inputs as u64) * NOTE_ZAT - 10_000_000; // leave fee room
                let t = Instant::now();
                let r = zecd
                    .call("sendtoaddress", json!([funder_ua, zec_str(amount_zat)]))
                    .await;
                let elapsed = ms(t.elapsed());
                match r {
                    Ok(_) => {
                        eprintln!(
                            "BENCH send label={label} round={round} i={i} inputs~{inputs} ms={elapsed}"
                        );
                        send_ms.push(json!({"i": i, "inputs": inputs, "ms": elapsed}));
                    }
                    Err(e) => {
                        eprintln!("BENCH send label={label} round={round} i={i} FAILED: {e}");
                        send_ms.push(json!({"i": i, "inputs": inputs, "error": e.to_string()}));
                    }
                }
                mine_and_sync(&zebrad, &zecd, 4).await;
            }

            // Fan-out: one z_sendmany paying `fanout` own addresses.
            let mut fanout_ms = None;
            if fanout > 0 {
                let mut outs = Vec::new();
                for _ in 0..fanout {
                    let a = zecd
                        .call("getnewaddress", json!([]))
                        .await
                        .expect("getnewaddress");
                    outs.push(
                        json!({"address": a.as_str().unwrap(), "amount": zec_str(1_000_000)}),
                    );
                }
                let from = addrs[0].clone();
                let t = Instant::now();
                let opid = zecd
                    .call("z_sendmany", json!([from, outs]))
                    .await
                    .expect("z_sendmany");
                let status = zecd
                    .call("z_waitforoperation", json!([opid, 600]))
                    .await
                    .expect("z_waitforoperation");
                let elapsed = ms(t.elapsed());
                let ok = status.get("status").and_then(|s| s.as_str()) == Some("success");
                eprintln!(
                    "BENCH fanout label={label} round={round} outputs={fanout} ms={elapsed} ok={ok} status={status}"
                );
                fanout_ms = Some(json!({"outputs": fanout, "ms": elapsed, "ok": ok}));
                mine_and_sync(&zebrad, &zecd, 4).await;
            }

            let balance = zecd
                .call("getbalance", json!([]))
                .await
                .expect("getbalance");
            let mnemonic = zecd.mnemonic.clone().expect("fresh wallet mnemonic");
            zecd.shutdown().await.expect("stop");

            // Restore from seed and time the full-chain scan.
            let mut rcfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("port"));
            rcfg.restore_mnemonic = Some(mnemonic);
            rcfg.birthday = Some(2);
            let chain_tip = tip(&zebrad).await;
            let t = Instant::now();
            let restored = Zecd::start(&rcfg).await.expect("start restore");
            let restore_up_ms = ms(t.elapsed());
            eprintln!(
                "BENCH port={} label={} round={} restore",
                rcfg.rpc_port, label, round
            );
            restored
                .wait_until_synced(chain_tip, SYNC_TIMEOUT)
                .await
                .expect("restore sync");
            let restore_scan_ms = ms(t.elapsed());
            let rbalance = restored
                .call("getbalance", json!([]))
                .await
                .expect("getbalance");
            eprintln!(
                "BENCH restore label={label} round={round} height={chain_tip} scan_ms={restore_scan_ms} balance={rbalance} (authoring {balance})"
            );
            restored.shutdown().await.expect("stop restored");

            results.push(json!({
                "label": label, "round": round, "version": version, "port": cfg.rpc_port,
                "restore_port": rcfg.rpc_port,
                "startup_ms": startup_ms, "fund_scan_ms": fund_scan_ms,
                "sends": send_ms, "fanout": fanout_ms,
                "restore_up_ms": restore_up_ms, "restore_scan_ms": restore_scan_ms,
                "restore_height": chain_tip,
                "balance_match": balance == rbalance,
            }));
        }
    }
    eprintln!("BENCH_RESULTS {}", serde_json::to_string(&results).unwrap());
}
