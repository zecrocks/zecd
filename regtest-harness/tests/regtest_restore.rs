//! Wallet lifecycle test: graceful `stop`, then restore-from-mnemonic.
//!
//! A wallet's Unified Full Viewing Key is a deterministic function of its seed (one ZIP-32
//! account), so a restored wallet exporting the identical UFVK proves the mnemonic
//! round-trip end to end - init's stdout phrase, `init --restore --birthday` (phrase on
//! stdin), and the daemon coming up on the restored DB - without needing funds. (The
//! funds-restore flow is validated manually on testnet; see the project docs. Receive *addresses*
//! are deliberately not compared: librustzcash picks shielded diversifier indexes from the
//! wall clock, so two `getnewaddress` calls minutes apart yield different diversified
//! addresses of the same account.) Along the way the original daemon is shut down with the
//! `stop` RPC, asserting bitcoind's reply shape and a clean exit - the only live
//! verification of `stop` semantics.
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
async fn regtest_stop_and_restore() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_stop_and_restore: set ZECD_REGTEST_EXTENDED=1 to run the extended \
             tier (see README.md)."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin)) =
        (resolve_bin("ZEBRAD_BIN"), resolve_bin("LIGHTWALLETD_BIN"))
    else {
        eprintln!(
            "SKIP regtest_stop_and_restore: set ZEBRAD_BIN and LIGHTWALLETD_BIN (see \
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

    // 1. The original wallet: capture its generated mnemonic and its UFVK (the
    //    deterministic fingerprint of the seed's key material; exported before `stop`
    //    tears down the datadir).
    let cfg_a = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd_a = Zecd::start(&cfg_a)
        .await
        .expect("start the original wallet");
    zecd_a
        .wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("the original wallet scans the chain");
    let mnemonic = zecd_a
        .mnemonic
        .clone()
        .expect("a fresh init prints its mnemonic on stdout");
    assert_eq!(
        mnemonic.split_whitespace().count(),
        24,
        "init emits a 24-word phrase: {mnemonic}"
    );
    let addr_a = zecd_a
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress on the original wallet")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_a.starts_with("uregtest1"), "{addr_a}");
    let ufvk_a = zecd_a
        .export_ufvk("default")
        .expect("export-ufvk on the original wallet");

    // 2. Graceful shutdown: `stop` answers "zecd stopping" and the process exits 0
    //    (asserted inside `shutdown`).
    zecd_a.shutdown().await.expect("graceful stop");

    // 3. Restore from the captured mnemonic on a fresh datadir. Birthday 2 is the lowest
    //    height with a fetchable tree state (the funder uses the same convention).
    let mut cfg_b = ZecdConfig::new(lwd.grpc_port, pick_port().expect("pick zecd rpc port"));
    cfg_b.restore_mnemonic = Some(mnemonic);
    cfg_b.birthday = Some(2);
    let zecd_b = Zecd::start(&cfg_b)
        .await
        .expect("start the restored wallet");
    assert!(
        zecd_b.mnemonic.is_none(),
        "a restore prints no mnemonic (nothing new to back up)"
    );
    zecd_b
        .wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("the restored wallet scans from its birthday to the tip");

    // Same seed, fresh DB: the restored wallet derives the identical UFVK - same account
    // key material, so every address either instance ever issued belongs to it.
    assert_eq!(
        zecd_b
            .export_ufvk("default")
            .expect("export-ufvk on the restored wallet"),
        ufvk_a,
        "the restored wallet derives the same key material as the original"
    );
    let addr_b = zecd_b
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress on the restored wallet")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert!(addr_b.starts_with("uregtest1"), "{addr_b}");

    // The restored wallet is empty and healthy.
    let bal = zecd_b
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(bal.as_f64(), Some(0.0), "no phantom funds after restore");
    let txs = zecd_b
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    assert_eq!(
        txs.as_array().map(|a| a.len()),
        Some(0),
        "no phantom history after restore"
    );
    let wi = zecd_b
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(wi["walletname"], json!("default"), "{wi}");
}
