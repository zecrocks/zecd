//! Multiwallet test: two `[wallets.*]` entries served by one daemon. Exercises the
//! `/wallet/<name>` routing, `listwallets`, the `-18` unknown-wallet error, and the
//! per-wallet isolation of seeds (distinct addresses), labels, and encryption state -
//! none of which the single-wallet suites can reach.
//!
//! Extended tier: set `ZECD_REGTEST_EXTENDED=1` (plus ZEBRAD_BIN / LIGHTWALLETD_BIN).
//! Skips cleanly otherwise.

use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{
    extended_enabled, pick_port, resolve_bin, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

const INITIAL_BLOCKS: u32 = 10;
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
async fn regtest_multiwallet_routing_and_isolation() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_multiwallet_routing_and_isolation: set ZECD_REGTEST_EXTENDED=1 to \
             run the extended tier (see README.md)."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_multiwallet_routing_and_isolation: set ZEBRAD_BIN and \
             LIGHTWALLETD_BIN (see README.md). The harness still compiled and linked."
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine the initial chain");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("launch lightwalletd");

    let mut cfg = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.extra_wallets = vec!["w2".to_string()];
    let zecd = Zecd::start(&cfg).await.expect("start zecd with two wallets");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans the chain");

    // Both wallets are loaded and reported (sorted, as bitcoind does).
    let lw = zecd.call("listwallets", json!([])).await.expect("listwallets");
    assert_eq!(lw, json!(["default", "w2"]), "both wallets are served");

    // /wallet/<name> routes to the named wallet: each derives from its own seed, and
    // getwalletinfo names the wallet that answered.
    let addr_default = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress (default)")
        .as_str()
        .expect("address is a string")
        .to_string();
    let addr_w2 = zecd
        .call_wallet("w2", "getnewaddress", json!([]))
        .await
        .expect("getnewaddress (/wallet/w2)")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_w2.starts_with("uregtest1"), "w2 address: {addr_w2}");
    assert_ne!(addr_default, addr_w2, "the wallets hold distinct seeds");
    let wi = zecd
        .call_wallet("w2", "getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo (/wallet/w2)");
    assert_eq!(wi["walletname"], json!("w2"), "{wi}");
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo (default)");
    assert_eq!(wi["walletname"], json!("default"), "{wi}");

    // An unknown wallet path is Bitcoin Core's -18 (wallet not found).
    let err = zecd
        .call_wallet("nope", "getbalance", json!([]))
        .await
        .expect_err("an unknown wallet must fail");
    assert_eq!(err.code(), Some(-18), "expected -18, got: {err}");

    // Labels are per-wallet side-state: a label set in w2 never shows in default.
    zecd.call_wallet("w2", "setlabel", json!([addr_w2, "w2-label"]))
        .await
        .expect("setlabel in w2");
    let labels = zecd
        .call_wallet("w2", "listlabels", json!([]))
        .await
        .expect("listlabels (w2)");
    assert!(
        labels.as_array().expect("array").contains(&json!("w2-label")),
        "w2 sees its label: {labels}"
    );
    let labels = zecd.call("listlabels", json!([])).await.expect("listlabels (default)");
    assert!(
        !labels.as_array().expect("array").contains(&json!("w2-label")),
        "labels do not leak across wallets: {labels}"
    );

    // Encryption state is per-wallet: encrypting w2 locks it (send -> -13, wrong passphrase
    // -14) while the default wallet stays unencrypted (passphrase RPCs -15, send still fails
    // on funds with -6).
    zecd.call_wallet("w2", "encryptwallet", json!(["w2-pass"]))
        .await
        .expect("encryptwallet on w2");
    let err = zecd
        .call_wallet("w2", "sendtoaddress", json!([addr_default, 0.1]))
        .await
        .expect_err("locked w2 must refuse to send");
    assert_eq!(err.code(), Some(-13), "expected -13, got: {err}");
    let err = zecd
        .call_wallet("w2", "walletpassphrase", json!(["wrong", 60]))
        .await
        .expect_err("a wrong passphrase must be rejected");
    assert_eq!(err.code(), Some(-14), "expected -14, got: {err}");
    let err = zecd
        .call("walletpassphrase", json!(["x", 60]))
        .await
        .expect_err("the default wallet is still unencrypted");
    assert_eq!(err.code(), Some(-15), "expected -15, got: {err}");
    let err = zecd
        .call("sendtoaddress", json!([addr_w2, 0.1]))
        .await
        .expect_err("the default wallet has no funds");
    assert_eq!(err.code(), Some(-6), "expected -6, got: {err}");

    // w2 unlocks with the real passphrase and is back to failing on funds, not on the lock.
    zecd.call_wallet("w2", "walletpassphrase", json!(["w2-pass", 60]))
        .await
        .expect("the real passphrase unlocks w2");
    let err = zecd
        .call_wallet("w2", "sendtoaddress", json!([addr_default, 0.1]))
        .await
        .expect_err("w2 has no funds either");
    assert_eq!(err.code(), Some(-6), "expected -6, got: {err}");
}
