//! Wallet lifecycle test: graceful `stop`, then restore-from-mnemonic.
//!
//! A fresh wallet's first receive address is a deterministic function of its seed (one
//! ZIP-32 account, first diversifier index), so a restored wallet deriving the same first
//! address as the original proves the mnemonic round-trip end to end - init's stdout
//! phrase, `init --restore --birthday` (phrase on stdin), and the daemon coming up on the
//! restored DB - without needing funds. (The funds-restore flow is validated manually on
//! testnet; see the project docs.) Along the way the original daemon is shut down with the `stop`
//! RPC, asserting bitcoind's reply shape and a clean exit - the only live verification of
//! `stop` semantics.
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

    // 1. The original wallet: capture its generated mnemonic and first receive address.
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

    // Same seed, fresh DB: the first derived address matches the original wallet's.
    let addr_b = zecd_b
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress on the restored wallet")
        .as_str()
        .expect("address is a string")
        .to_string();
    assert_eq!(
        addr_b, addr_a,
        "the restored wallet derives the same first address as the original"
    );

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
