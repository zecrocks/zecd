//! Watch-only (UFVK) wallet lifecycle test.
//!
//! Drives the full operator flow end to end: a spending wallet exports its Unified Full
//! Viewing Key (`zecd export-ufvk`), a second zecd initialises watch-only from it
//! (`init --ufvk`), and both daemons run side by side against the same chain. The watch-only
//! wallet must re-export **the identical UFVK** (the key-material round trip that makes its
//! invoices spendable by the paired wallet - same-index address equality is proven offline,
//! since librustzcash's shielded diversifier indexes are clock-derived), report
//! `private_keys_enabled: false`, and refuse spending and encryption RPCs with Bitcoin
//! Core's codes (-4/-16/-15) - while the read surface (balances, history, `getnewaddress`)
//! stays fully available.
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
async fn regtest_watch_only_ufvk() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_watch_only_ufvk: set ZECD_REGTEST_EXTENDED=1 to run the extended \
             tier (see README.md)."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_watch_only_ufvk: set ZEBRAD_BIN and LIGHTWALLETD_BIN (see \
             README.md). The harness still compiled and linked."
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

    // 1. The spending wallet (its address is used later for per-address flag checks).
    let cfg_a = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd_a = Zecd::start(&cfg_a)
        .await
        .expect("start the spending wallet");
    zecd_a
        .wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("the spending wallet scans the chain");
    let addr_a = zecd_a
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress on the spending wallet")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_a.starts_with("uregtest1"), "{addr_a}");

    // 2. Export the UFVK from the running daemon's datadir (read-only; no spending material).
    let ufvk = zecd_a.export_ufvk("default").expect("zecd export-ufvk");
    assert!(
        ufvk.starts_with("uviewregtest1"),
        "regtest UFVKs use the uviewregtest1 HRP, got {ufvk}"
    );

    // 3. The watch-only wallet: init --ufvk on a fresh datadir, against the same chain.
    //    Birthday 2 is the lowest height with a fetchable tree state (restore convention).
    let mut cfg_b = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    cfg_b.ufvk = Some(ufvk);
    cfg_b.birthday = Some(2);
    let zecd_b = Zecd::start(&cfg_b)
        .await
        .expect("start the watch-only wallet");
    assert!(
        zecd_b.mnemonic.is_none(),
        "a watch-only init has no mnemonic to print"
    );
    zecd_b
        .wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("the watch-only wallet scans from its birthday to the tip");

    // Same UFVK, fresh DB: the watch-only wallet re-exports the exact key it was built
    // from - the key-material round trip that makes its invoices spendable by the paired
    // wallet. (Address *values* are deliberately not compared across the two daemons:
    // librustzcash picks shielded diversifier indexes from the wall clock, so two wallets'
    // `getnewaddress` results only coincide within the same second. Same-index address
    // equality is proven offline by
    // `regtest_tests::watch_only_ufvk_wallet_pairs_with_spending_wallet`.)
    assert_eq!(
        zecd_b.export_ufvk("default").expect("export-ufvk on B"),
        zecd_a.export_ufvk("default").expect("export-ufvk on A"),
        "the watch-only wallet carries the spending wallet's exact key material"
    );
    let addr_b = zecd_b
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress works from the viewing key alone")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_b.starts_with("uregtest1"), "{addr_b}");

    // 4. The wallet self-reports as watch-only the way Bitcoin Core master does: the
    //    wallet-level `private_keys_enabled` flag. `getaddressinfo` is byte-identical on
    //    both wallets - master's `iswatchonly` is deprecated/always-false and `solvable`
    //    ignores the lack of private keys.
    let wi = zecd_b
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(
        wi["private_keys_enabled"],
        json!(false),
        "watch-only wallets report private_keys_enabled: false - {wi}"
    );
    // Each wallet's view of its own issued address carries the same flags - watch-only
    // changes nothing at the per-address level.
    for (zecd, addr) in [(&zecd_b, &addr_b), (&zecd_a, &addr_a)] {
        let ai = zecd
            .call("getaddressinfo", json!([addr]))
            .await
            .expect("getaddressinfo");
        assert_eq!(ai["ismine"], json!(true), "{ai}");
        assert_eq!(ai["iswatchonly"], json!(false), "{ai}");
        assert_eq!(ai["solvable"], json!(true), "{ai}");
    }

    // 5. Spending refuses with Bitcoin Core's -4 (Private keys are disabled), before any
    //    balance check; encryptwallet is Core's -16 (nothing to encrypt) and the passphrase
    //    RPCs -15.
    let err = zecd_b
        .call("sendtoaddress", json!([addr_b, 0.1]))
        .await
        .expect_err("sendtoaddress on a watch-only wallet must fail");
    assert_eq!(err.code(), Some(-4), "{err}");
    assert!(
        err.to_string().contains("Private keys are disabled"),
        "{err}"
    );
    let err = zecd_b
        .call("encryptwallet", json!(["pw"]))
        .await
        .expect_err("encryptwallet on a watch-only wallet must fail");
    assert_eq!(err.code(), Some(-16), "{err}");
    assert!(err.to_string().contains("nothing to encrypt"), "{err}");
    let err = zecd_b
        .call("walletpassphrase", json!(["pw", 60]))
        .await
        .expect_err("walletpassphrase on a watch-only wallet must fail");
    assert_eq!(err.code(), Some(-15), "{err}");

    // 6. The read surface stays fully available, empty but well-formed.
    let bal = zecd_b
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(bal.as_f64(), Some(0.0), "fresh watch-only wallet is empty");
    let txs = zecd_b
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert_eq!(txs.as_array().map(|a| a.len()), Some(0));
}
