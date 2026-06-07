//! End-to-end regtest test: zebra (Regtest) + lightwalletd, driven through zecd's JSON-RPC.
//!
//! Orchestration - spinning up zebrad + lightwalletd and, crucially, MINING blocks - is
//! delegated to `zingo-infra-testutils`. Zebra has no `generate` RPC; blocks are produced via
//! getblocktemplate/submitblock, which that crate wraps as `validator().generate_blocks(n)`.
//!
//! VALIDATION STATUS: this test needs a Linux host with network access (zingo-infra downloads
//! zebrad/lightwalletd) and the built `zecd` release binary. It runs in CI
//! (`.github/workflows/regtest.yml`), NOT in zecd's offline `cargo test` tier. The
//! `zingo_infra_testutils` calls below target that crate's `services` API and are exercised /
//! corrected in CI; everything driven through `zecd`'s JSON-RPC is stable and authoritative.
//!
//! FUNDING CAVEAT: regtest can't fund an Orchard-only wallet on-chain (zebra #9082), so this
//! covers sync, addresses, the RPC surface and insufficient-funds - not a funded spend. Funded
//! semantics are covered by zecd's offline lifecycle test and the live testnet flow.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{Zecd, ZecdConfig};

// zingo-infra's local-net orchestrator. `ZebradConfig::default()` selects Network::Regtest with
// every upgrade (incl. NU5/Orchard) active at height 1 - matching zecd's `network::regtest()`.
// The `Validator` trait brings `generate_blocks` into scope.
use zingo_infra_testutils::services::{
    indexer::{Lightwalletd, LightwalletdConfig},
    validator::{Validator, Zebrad, ZebradConfig},
    LocalNet,
};

const INITIAL_BLOCKS: u32 = 10;
const SYNC_TIMEOUT: Duration = Duration::from_secs(90);

#[tokio::test]
async fn regtest_end_to_end() {
    // 1. Launch zebra (Regtest) + lightwalletd; `launch` wires lightwalletd's validator port to
    //    zebra's RPC port automatically (and overwrites `zcashd_conf`). LightwalletdConfig has no
    //    Default - `listen_port: None` picks a free port; `lightwalletd_bin: None` uses the
    //    binary zingo-infra downloads.
    let net = LocalNet::<Lightwalletd, Zebrad>::launch(
        LightwalletdConfig {
            lightwalletd_bin: None,
            listen_port: None,
            zcashd_conf: PathBuf::new(),
        },
        ZebradConfig::default(),
    )
    .await;

    // 2. Mine an initial chain so zecd has a tip above the wallet birthday (regtest genesis).
    net.validator()
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial regtest blocks");

    // 3. Start zecd pointed at this lightwalletd. `indexer().port()` is the lightwalletd gRPC
    //    port (upstream getter - adjust here if the zingo-infra API differs).
    let cfg = ZecdConfig {
        lightwalletd_port: net.indexer().port(),
        rpc_port: 18232,
        rpc_user: "u".into(),
        rpc_password: "p".into(),
    };
    let zecd = Zecd::start(&cfg).await.expect("start zecd against regtest lightwalletd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans to the regtest tip");

    // ---- zecd RPC assertions (the stable, authoritative part of this test) ----

    // Chain identity + height.
    let info = zecd.call("getblockchaininfo", json!([])).await.expect("getblockchaininfo");
    assert_eq!(info["chain"], "regtest", "getblockchaininfo.chain");
    assert_eq!(info["blocks"].as_u64().unwrap(), INITIAL_BLOCKS as u64);

    // Mining more blocks advances zecd's view deterministically (confirmations machinery).
    net.validator().generate_blocks(5).await.expect("mine 5 more");
    zecd.wait_until_synced((INITIAL_BLOCKS + 5) as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd follows the new blocks");
    assert_eq!(zecd.block_count().await.unwrap(), (INITIAL_BLOCKS + 5) as u64);

    // Addresses: getnewaddress yields a regtest Unified Address; validateaddress agrees.
    let addr = zecd.call("getnewaddress", json!([])).await.expect("getnewaddress");
    let addr = addr.as_str().expect("getnewaddress returns a string").to_string();
    assert!(addr.starts_with("uregtest1"), "expected a uregtest1 UA, got {addr}");
    let val = zecd.call("validateaddress", json!([addr])).await.expect("validateaddress");
    assert_eq!(val["isvalid"], true, "own address validates on regtest");

    // Empty wallet: zero balance, no history, no notes.
    let bal = zecd.call("getbalance", json!([])).await.expect("getbalance");
    assert_eq!(bal.as_f64().unwrap_or(-1.0), 0.0, "fresh wallet balance is 0");
    assert!(zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions")
        .as_array()
        .unwrap()
        .is_empty());
    assert!(zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent")
        .as_array()
        .unwrap()
        .is_empty());

    // Insufficient funds: sending from an empty wallet returns Bitcoin Core's -6.
    let err = zecd
        .call("sendtoaddress", json!([addr, 0.1]))
        .await
        .expect_err("send from an empty wallet must fail");
    assert_eq!(
        err.code(),
        Some(-6),
        "expected RPC_WALLET_INSUFFICIENT_FUNDS (-6), got: {err}"
    );
}
