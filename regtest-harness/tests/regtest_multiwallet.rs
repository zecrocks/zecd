//! Multiwallet tests: one spending wallet plus any number of watch-only (UFVK) wallets, served
//! by a single daemon. Exercises `/wallet/<name>` routing, `listwallets`, the `-18`
//! unknown-wallet error, per-wallet label isolation, and the **single-spending-wallet
//! invariant** (zecd loads at most one wallet with spending keys; a second one makes the daemon
//! refuse to start) - none of which the single-wallet suites can reach.
//!
//! Extended tier: set `ZECD_REGTEST_EXTENDED=1` (plus ZEBRAD_BIN).
//! Skips cleanly otherwise.

use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{extended_enabled, pick_port, resolve_bin, Zebrad, Zecd, ZecdConfig};

const INITIAL_BLOCKS: u32 = 10;
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// One spending wallet (`default`) plus two watch-only replicas (`w2`, `w3`): the supported
/// multiwallet shape. Proves routing, `listwallets`, watch-only behavior, per-wallet label
/// isolation, and that the lone spending wallet keeps its full spending surface.
#[tokio::test]
async fn regtest_multiwallet_routing_and_isolation() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_multiwallet_routing_and_isolation: set ZECD_REGTEST_EXTENDED=1 to \
             run the extended tier (see README.md)."
        );
        return;
    }
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_multiwallet_routing_and_isolation: set ZEBRAD_BIN \
             (see README.md). The harness still compiled and linked."
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine the initial chain");

    // `default` spends; `w2` and `w3` are watch-only replicas of it (any number are allowed
    // alongside the single spender).
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.extra_watch_only_wallets = vec!["w2".to_string(), "w3".to_string()];
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with one spending + two watch-only wallets");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans the chain");

    // All three wallets are loaded and reported (sorted, as bitcoind does).
    let lw = zecd
        .call("listwallets", json!([]))
        .await
        .expect("listwallets");
    assert_eq!(
        lw,
        json!(["default", "w2", "w3"]),
        "the spending wallet and both watch-only replicas are served"
    );

    // /wallet/<name> routes to the named wallet: getwalletinfo names the wallet that answered,
    // and only the spending wallet reports private_keys_enabled.
    let wi_default = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo (default)");
    assert_eq!(wi_default["walletname"], json!("default"), "{wi_default}");
    assert_eq!(
        wi_default["private_keys_enabled"],
        json!(true),
        "the default wallet holds spending keys: {wi_default}"
    );
    for w in ["w2", "w3"] {
        let wi = zecd
            .call_wallet(w, "getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo (/wallet/<name>)");
        assert_eq!(wi["walletname"], json!(w), "{wi}");
        assert_eq!(
            wi["private_keys_enabled"],
            json!(false),
            "watch-only replicas report private_keys_enabled: false - {wi}"
        );
    }

    // getnewaddress works on every wallet (the watch-only replicas derive from the viewing key).
    let addr_default = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress (default)")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(
        addr_default.starts_with("uregtest1"),
        "default address: {addr_default}"
    );
    let addr_w2 = zecd
        .call_wallet("w2", "getnewaddress", json!([]))
        .await
        .expect("getnewaddress (/wallet/w2)")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_w2.starts_with("uregtest1"), "w2 address: {addr_w2}");

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
        labels
            .as_array()
            .expect("array")
            .contains(&json!("w2-label")),
        "w2 sees its label: {labels}"
    );
    let labels = zecd
        .call("listlabels", json!([]))
        .await
        .expect("listlabels (default)");
    assert!(
        !labels
            .as_array()
            .expect("array")
            .contains(&json!("w2-label")),
        "labels do not leak across wallets: {labels}"
    );

    // The watch-only replicas refuse spending and passphrase RPCs with Bitcoin Core's codes
    // (-4 private keys disabled, -15 passphrase RPC unsupported), independently per wallet.
    for w in ["w2", "w3"] {
        let err = zecd
            .call_wallet(w, "sendtoaddress", json!([addr_default, 0.1]))
            .await
            .expect_err("a watch-only wallet must refuse to send");
        assert_eq!(err.code(), Some(-4), "expected -4 on {w}, got: {err}");
        let err = zecd
            .call_wallet(w, "walletpassphrase", json!(["pw", 60]))
            .await
            .expect_err("a watch-only wallet has no passphrase");
        assert_eq!(err.code(), Some(-15), "expected -15 on {w}, got: {err}");
    }

    // The lone spending wallet keeps its full spending surface: passphrase RPCs are -15 while
    // it is unencrypted, and a send fails only on funds (-6), not on private-key availability.
    let err = zecd
        .call("walletpassphrase", json!(["x", 60]))
        .await
        .expect_err("the default wallet is unencrypted");
    assert_eq!(err.code(), Some(-15), "expected -15, got: {err}");
    let err = zecd
        .call("sendtoaddress", json!([addr_w2, 0.1]))
        .await
        .expect_err("the default wallet has no funds");
    assert_eq!(err.code(), Some(-6), "expected -6, got: {err}");
}

/// The single-spending-wallet invariant, enforced at `init` time: with the spending `default`
/// wallet already present, creating a second spending wallet is refused before any work is done
/// (the operator must use `--ufvk` for a watch-only wallet, or convert/remove the existing
/// one). The watch-only suite covers the allowed direction; this is the forbidden one.
#[tokio::test]
async fn regtest_second_spending_wallet_refused_at_init() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_second_spending_wallet_refused_at_init: set ZECD_REGTEST_EXTENDED=1 \
             to run the extended tier (see README.md)."
        );
        return;
    }
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_second_spending_wallet_refused_at_init: set ZEBRAD_BIN \
             (see README.md). The harness still compiled and linked."
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin).await.expect("launch zebrad");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine the initial chain");

    // Config lists both `default` and `w2` as spending wallets; init `default`, then attempt to
    // init `w2` - the guard sees the existing spender and refuses.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.extra_wallets = vec!["w2".to_string()];
    let stderr = Zecd::init_second_spending_expect_refusal(&cfg, "w2")
        .await
        .expect("a second spending wallet must be refused at init");
    assert!(
        stderr.contains("spending wallet"),
        "the refusal should explain the single-spending-wallet rule; stderr was:\n{stderr}"
    );
}
