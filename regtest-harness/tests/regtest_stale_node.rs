//! A node that was never upgraded for a network upgrade this zecd build follows.
//!
//! A Zakura 1.5.1 testnet node that never adopted NU7 forked off at the activation height and
//! stayed there, and zecd called it usable - `chain-info` reported `usable: true`, and a daemon
//! pointed at it synced to the fork's tip and reported ready. The outdated-build check only
//! looked one way (upgrades the node knows and the build does not).
//!
//! This stands that node up: a zebrad whose config leaves NU7 out, under a zecd that activates
//! NU7 at `ZECD_REGTEST_NU7_HEIGHT`. Past that height the node keeps mining on the NU6.3 rules,
//! exactly as the stale node did. The contracts:
//!
//! 1. before activation the wallet syncs normally, and `chain-info` already flags the node
//!    (the advance warning; zebra only - lightwalletd reports no upgrade map to read it from);
//! 2. once the node's chain crosses the height, the wallet stops scanning short of it, `/readyz`
//!    answers 503 with `upstream_not_upgraded`, `/status` and `getblockchaininfo.warnings` carry
//!    the reason, and `chain-info` exits nonzero with the finding active - on both backends,
//!    light mode through the branch ruling the node's tip.
//!
//! No funder: nothing here needs money, so the bring-up is a bare chain. Skips cleanly when the
//! node binary is not provisioned, or when `ZECD_REGTEST_NU7_HEIGHT` is unset (there is then no
//! upgrade for the node to have missed).

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{
    attach_backend, pick_port, regtest_nu7_height, resolve_node_bin, zecd_backend_is_lwd,
    RegtestNode, Zebrad, Zecd, ZecdConfig,
};

const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the actor may take to notice the crossing: one idle tick to see the new tip, plus
/// slack for a reconnect attempt in light mode.
const REFUSAL_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn regtest_stale_node_is_refused_past_the_upgrade_it_missed() {
    let Some(node_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_stale_node: set {}.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };
    let Some(nu7) = regtest_nu7_height() else {
        eprintln!("SKIP regtest_stale_node: ZECD_REGTEST_NU7_HEIGHT is unset, so there is no NU7 for the node to miss.");
        return;
    };
    let lwd_mode = zecd_backend_is_lwd();

    let zebrad = Zebrad::start_without_nu7(&node_bin)
        .await
        .expect("launch a node without NU7");
    let before = nu7 - 3;
    zebrad
        .generate_blocks(before)
        .await
        .expect("mine up to just short of NU7");

    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let _lwd = attach_backend(&mut cfg, zebrad.rpc_port)
        .await
        .expect("attach the configured backend");
    let zecd = Zecd::start(&cfg).await.expect("start zecd");

    // 1. Before activation the node's chain is the network's: the wallet syncs and is ready.
    zecd.wait_until_synced(before as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans the pre-activation chain");
    // Scanned is not ready: the post-scan enhancement backlog drains first, so wait for it.
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        let (status, body) = zecd.health_get("/readyz").await.expect("/readyz");
        if status.as_u16() == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never ready before activation: {status} {body}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let bci = zecd
        .call("getblockchaininfo", json!([]))
        .await
        .expect("getblockchaininfo");
    assert_eq!(bci["warnings"], json!(""), "no warning yet: {bci}");

    let (ok, report) = zecd.chain_info().expect("chain-info before activation");
    assert!(ok, "only an active finding fails chain-info: {report}");
    let findings = not_upgraded_findings(&report);
    if lwd_mode {
        // lightwalletd reports no upgrade map, so the advance warning has nothing to read; the
        // tip's branch is still the one this build expects.
        assert!(findings.is_empty(), "{report}");
        assert_eq!(report["usable"], json!(true), "{report}");
    } else {
        assert_eq!(
            findings.len(),
            1,
            "the node's map stops short of NU7: {report}"
        );
        assert_eq!(findings[0]["name"], json!("NU7"), "{report}");
        assert_eq!(
            findings[0]["active"],
            json!(false),
            "pending before the height: {report}"
        );
        assert_eq!(findings[0]["activation_height"], json!(nu7), "{report}");
        assert_eq!(
            report["usable"],
            json!(false),
            "a scheduled fork is not usable: {report}"
        );
    }

    // 2. Cross the height. The node mines on, on the old rules.
    zebrad
        .generate_blocks(6)
        .await
        .expect("mine past NU7 on the old rules");

    let deadline = Instant::now() + REFUSAL_TIMEOUT;
    let body = loop {
        let (status, body) = zecd.health_get("/readyz").await.expect("/readyz");
        if status.as_u16() == 503 && body["reason"] == json!("upstream_not_upgraded") {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never refused the un-upgraded node: /readyz {status} {body}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    eprintln!("refused: {body}");

    let scanned = zecd
        .call("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("height");
    assert!(
        scanned < nu7 as u64,
        "the wallet scanned the fork: fully scanned {scanned}, NU7 at {nu7}"
    );

    let (_, status) = zecd.health_get("/status").await.expect("/status");
    let refusal = status["wallets"]["default"]["upstream_refusal"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        refusal.contains("NU7") && refusal.contains("has not adopted"),
        "/status names the refusal: {status}"
    );
    let bci = zecd
        .call("getblockchaininfo", json!([]))
        .await
        .expect("getblockchaininfo while refused");
    assert_eq!(
        bci["warnings"],
        json!(refusal),
        "warnings carries it: {bci}"
    );
    assert_eq!(
        bci["upgrades"][format!("{:08x}", 0x7719_0ad9u32)]["name"],
        json!("NU7"),
        "getblockchaininfo reports this build's schedule, whatever the node's: {bci}"
    );

    let (ok, report) = zecd.chain_info().expect("chain-info past activation");
    assert!(!ok, "an active finding fails chain-info: {report}");
    assert_eq!(report["usable"], json!(false), "{report}");
    let findings = not_upgraded_findings(&report);
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["name"], json!("NU7"), "{report}");
    assert_eq!(findings[0]["active"], json!(true), "{report}");
    assert_eq!(findings[0]["activation_height"], json!(nu7), "{report}");

    drop(zecd);
}

/// The `upstream_not_upgraded` entries of a `chain-info --json` report.
fn not_upgraded_findings(report: &Value) -> Vec<Value> {
    report["unsupported_upgrades"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|u| u["kind"] == json!("upstream_not_upgraded"))
        .cloned()
        .collect()
}
