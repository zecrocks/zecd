//! Per-wallet backends: ONE daemon serving a zebra-backed spending wallet alongside a
//! lightwalletd-backed watch-only replica of it.
//!
//! Before `[wallets.<name>] server` existed this shape was unrepresentable - `[backend]` was
//! daemon-global, so every wallet in a process dialled the same upstream. The two wallets here
//! share a seed (the replica is a UFVK import of the spender), so they must converge on the
//! same chain view and the same balance while reaching the chain by completely different
//! routes: one parsing full blocks from zebrad's JSON-RPC, the other consuming compact blocks
//! over lightwalletd's gRPC. Any divergence is a real backend bug, and it is also the check
//! that per-wallet resolution actually reaches the actor rather than silently falling back to
//! the global endpoint.
//!
//! Extended tier: set `ZECD_REGTEST_EXTENDED=1`, plus `ZEBRAD_BIN` and `LIGHTWALLETD_BIN`
//! (lightwalletd is provisioned on the `zecd-lwd` CI leg, which is where this runs). Skips
//! cleanly otherwise.

use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{
    extended_enabled, pick_port, resolve_bin, start_funded_chain, Lightwalletd, Zecd, ZecdConfig,
};

/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
const SYNC_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_multibackend_wallets_share_one_daemon() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_multibackend_wallets_share_one_daemon: set ZECD_REGTEST_EXTENDED=1 to \
             run the extended tier."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_multibackend_wallets_share_one_daemon: set ZEBRAD_BIN and \
             LIGHTWALLETD_BIN. The harness still compiled and linked."
        );
        return;
    };

    // 1. One funded chain, and a lightwalletd serving the same zebrad.
    let (zebrad, funder) = start_funded_chain(&zebrad_bin)
        .await
        .expect("bring up a funded regtest chain");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start the replica's lightwalletd");

    // 2. One daemon, two upstreams: `default` inherits the global zebra:// endpoint, `replica`
    //    (a watch-only UFVK import of it) overrides `server` to the lightwalletd.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.extra_watch_only_wallets = vec!["replica".to_string()];
    cfg.wallet_servers = vec![(
        "replica".to_string(),
        format!("http://127.0.0.1:{}", lwd.grpc_port),
    )];
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with a zebra-backed and a lightwalletd-backed wallet");

    zecd.wait_until_synced_to_node(&zebrad, SYNC_TIMEOUT)
        .await
        .expect("the zebra-backed wallet scans the chain");

    // Both wallets are loaded and served by the one daemon.
    let wallets = zecd
        .call("listwallets", json!([]))
        .await
        .expect("listwallets");
    assert_eq!(wallets, json!(["default", "replica"]), "{wallets}");

    // 3. Fund the shared account and confirm it past the untrusted depth. The replica watches
    //    the same keys, so the payment must land on both sides.
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("an address string")
        .to_string();
    funder
        .send_many(&[(addr, FUND_ZATOSHIS)])
        .await
        .expect("fund the wallet under test");
    // `getbalance` applies the default confirmations policy, under which an externally
    // received (untrusted) note needs 10 confirmations before it counts, and the funder pays
    // this wallet's own external address. Mine past that depth, plus a couple for tip skew, as
    // every other funded binary here does; 2 blocks leaves both wallets correctly reporting 0.
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the funding");

    zecd.wait_until_synced_to_node(&zebrad, SYNC_TIMEOUT)
        .await
        .expect("the zebra-backed wallet scans the funding block");
    let tip = zecd
        .call("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("a height");
    zecd.wait_until_wallet_synced("replica", tip, SYNC_TIMEOUT)
        .await
        .expect("the lightwalletd-backed wallet scans the funding block");

    // 4. The two backends derive the same chain view and the same balance. Same seed, same
    //    chain, different routes to it.
    let (hash_zebra, hash_lwd) = (
        zecd.call("getbestblockhash", json!([]))
            .await
            .expect("getbestblockhash (zebra-backed)"),
        zecd.call_wallet("replica", "getbestblockhash", json!([]))
            .await
            .expect("getbestblockhash (lightwalletd-backed)"),
    );
    assert_eq!(
        hash_zebra, hash_lwd,
        "the two backends must agree on the chain tip"
    );

    let (balance_zebra, balance_lwd) = (
        zecd.call("getbalance", json!([]))
            .await
            .expect("getbalance (zebra-backed)"),
        zecd.call_wallet("replica", "getbalance", json!([]))
            .await
            .expect("getbalance (lightwalletd-backed)"),
    );
    assert_eq!(
        balance_zebra, balance_lwd,
        "the watch-only replica sees the same funds over its own upstream"
    );
    assert_ne!(
        balance_zebra,
        json!(0.0),
        "the funding payment must be visible: {balance_zebra}"
    );

    // 5. And the history agrees too - the replica recovered the receive from compact blocks.
    let txs_zebra = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions (zebra-backed)");
    let txs_lwd = zecd
        .call_wallet("replica", "listtransactions", json!([]))
        .await
        .expect("listtransactions (lightwalletd-backed)");
    let txids = |v: &serde_json::Value| -> Vec<String> {
        let mut ids: Vec<String> = v
            .as_array()
            .expect("an array")
            .iter()
            .map(|e| e["txid"].as_str().expect("a txid").to_string())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(
        txids(&txs_zebra),
        txids(&txs_lwd),
        "both wallets report the same transactions"
    );
}
