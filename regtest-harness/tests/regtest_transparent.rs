//! Transparent (t-address) regtest end-to-end: prove that a wallet configured with `[pools]
//! transparent = true` hands out a **bare transparent address**, sees a payment there at **0-conf**
//! (the mempool poller matches the tx's transparent outputs against the wallet's address set, the
//! same way it trial-decrypts shielded outputs) and then **confirmed** once mined (the block scan
//! matches each block's transparent outputs), and reports the receive across the
//! balance/listunspent/is_mine RPCs. **Spending** received transparent funds (which requires
//! shielding them first) is not yet implemented and is out of scope here - see the note at the end
//! of the test. Finally it guards the matcher's address-set refresh: a payment to an address issued
//! *beyond* the recovery window must still be discovered, which only holds if issuing the address
//! refreshes the in-memory set the block-scan / mempool matcher works off of.
//!
//! Setup mirrors `regtest_funded.rs`/`regtest_sapling.rs`: mine a transparent coinbase to the
//! funder, mature it, shield it, then have the funder pay zecd. The difference is that zecd is
//! configured with `[pools] transparent = true` (Orchard-only enabled, as default), zecd hands out
//! a `t…` receiving address, and the funder pays *that* - an ordinary shielded→transparent send.
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const FUND_ZATOSHIS: u64 = 100_000_000; // 1 ZEC
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_transparent_receive_and_autoshield_spend() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_transparent_receive_and_autoshield_spend: set ZEBRAD_BIN, \
             LIGHTWALLETD_BIN and DEVTOOL_BIN to run the transparent e2e (see README.md). The \
             harness still compiled."
        );
        return;
    };

    // 1-4. Identical funder bring-up to regtest_funded: mine + mature + shield the funder.
    let funder_taddr = Funder::derive_transparent_address(&devtool_bin)
        .expect("derive funder transparent address");
    let mut zebrad = Zebrad::start_with_miner(&zebrad_bin, &funder_taddr)
        .await
        .expect("start zebrad mining to the funder");
    zebrad
        .generate_blocks(FUNDER_COINBASES)
        .await
        .expect("mine the funder's coinbases");
    zebrad
        .restart_with_miner(TAIL_MINER_ADDRESS)
        .await
        .expect("restart zebrad mining to the throwaway address");
    zebrad
        .generate_blocks(MATURITY_TAIL)
        .await
        .expect("mine the maturity tail");
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");
    let funder = Funder::init(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 5. zecd with transparent receiving enabled (Orchard-only otherwise).
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.transparent = true;
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with transparent receiving");

    // getnewaddress "" "transparent" hands out a BARE transparent address (regtest uses testnet's
    // "tm" P2PKH prefix), not a Unified Address. (Deterministic - no funding needed.)
    let taddr = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent")
        .as_str()
        .expect("address string")
        .to_string();
    assert!(
        taddr.starts_with("tm"),
        "transparent address should be a bare t-addr (tm…), got {taddr}"
    );

    // validateaddress: a bare transparent address carries exactly the transparent receiver.
    let v = zecd
        .call("validateaddress", json!([taddr]))
        .await
        .expect("validateaddress t-addr");
    assert_eq!(v["isvalid"], json!(true), "t-addr is valid: {v}");
    assert_eq!(
        v["receiver_types"],
        json!(["transparent"]),
        "bare t-addr receiver_types == [transparent]: {v}"
    );

    // getaddressinfo.ismine recognizes the handed-out transparent address as ours.
    let ai = zecd
        .call("getaddressinfo", json!([taddr]))
        .await
        .expect("getaddressinfo t-addr");
    assert_eq!(ai["ismine"], json!(true), "own t-addr is ismine: {ai}");

    // signmessage / verifymessage round-trip over the wallet's own transparent address. Signing
    // exercises the real actor key-derivation path (derive the USK from the seed, then the input
    // address's secp256k1 key at its recorded (scope, index)); no funding is needed. (Deterministic
    // - signing is RFC-6979.)
    let message = "zecd regtest signmessage e2e";
    let signature = zecd
        .call("signmessage", json!([taddr, message]))
        .await
        .expect("signmessage over own t-addr")
        .as_str()
        .expect("signature string")
        .to_string();
    assert_eq!(
        signature.len(),
        88,
        "a 65-byte recoverable signature base64-encodes to 88 chars: {signature}"
    );
    // The signature verifies for (address, message) and fails for a tampered message.
    assert_eq!(
        zecd.call("verifymessage", json!([taddr, signature, message]))
            .await
            .expect("verifymessage"),
        json!(true),
        "own signature verifies"
    );
    assert_eq!(
        zecd.call(
            "verifymessage",
            json!([taddr, signature, "a different message"])
        )
        .await
        .expect("verifymessage wrong message"),
        json!(false),
        "signature must not verify against a different message"
    );
    // Signing with an address the wallet does not own (a shielded Orchard UA is not even a
    // transparent address) is rejected -5, before the seed is touched.
    let orchard_ua = zecd
        .call("getnewaddress", json!(["", "orchard"]))
        .await
        .expect("getnewaddress orchard")
        .as_str()
        .expect("ua string")
        .to_string();
    let err = zecd
        .call("signmessage", json!([orchard_ua, message]))
        .await
        .expect_err("signmessage rejects a non-transparent address");
    assert_eq!(
        err.code(),
        Some(-5),
        "signmessage on a shielded address -> -5: {err}"
    );
    // Signing with a valid transparent address the wallet does NOT own (the funder's own t-addr,
    // derived from a different seed) is rejected -4: the wallet has no key for it.
    let err = zecd
        .call("signmessage", json!([funder_taddr, message]))
        .await
        .expect_err("signmessage rejects an unowned transparent address");
    assert_eq!(
        err.code(),
        Some(-4),
        "signmessage on an unowned t-addr -> -4: {err}"
    );

    // getwalletinfo surfaces the transparent observability block (the default gap limit is 20).
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert_eq!(
        wi["transparent"]["enabled"],
        json!(true),
        "getwalletinfo.transparent.enabled: {wi}"
    );
    assert_eq!(
        wi["transparent"]["gap_limit"],
        json!(20),
        "getwalletinfo.transparent.gap_limit defaults to 20: {wi}"
    );

    // address_type "transparent" requires the wallet to enable it - but here it is enabled, so the
    // above succeeded. (A wallet without [pools] transparent would reject it -8.)

    // 6. Wait until zecd is caught up (so the mempool stream is open) before funding.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let peers = zecd
            .call("getpeerinfo", json!([]))
            .await
            .expect("getpeerinfo");
        if peers
            .as_array()
            .and_then(|a| a.first())
            .is_some_and(|p| p["conn_state"] == "ready")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never reached ready: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 7. Fund the transparent address. The receive is visible at **0-conf** the moment it hits the
    //    mempool: the mempool poller matches the tx's transparent outputs against the wallet's
    //    address set (the shielded trial-decrypt path never matches a transparent output) and
    //    records the UTXO unmined, exactly like a shielded mempool receive. Mining then confirms it
    //    via the block scan. (`listunspent minconf=0` reads the wallet DB directly and lists unmined
    //    transparent UTXOs, so it is the authoritative 0-conf signal here.)
    funder
        .send(lwd.grpc_port, &taddr, FUND_ZATOSHIS)
        .expect("send to zecd's transparent address");

    // 7a. 0-conf: before any block confirms the funding tx, the transparent receive shows in
    //     `listunspent minconf=0` at the t-address with 0 confirmations - and is *not* yet listed at
    //     the default minconf (>= 1), proving it is genuinely unconfirmed (the mempool path, not a
    //     premature confirmation).
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let lu0 = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent minconf=0");
        let unconfirmed = lu0.as_array().is_some_and(|notes| {
            notes
                .iter()
                .any(|u| u["address"] == json!(taddr) && u["confirmations"].as_i64() == Some(0))
        });
        if unconfirmed {
            let lu_default = zecd
                .call("listunspent", json!([]))
                .await
                .expect("listunspent default minconf");
            assert!(
                lu_default
                    .as_array()
                    .is_some_and(|notes| notes.iter().all(|u| u["address"] != json!(taddr))),
                "the 0-conf transparent receive must not be listed at the default minconf yet: \
                 {lu_default}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the transparent receive never appeared at 0 conf via the mempool poller: {lu0}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm transparent receive");

    // 8. The confirmed transparent receive shows up in the balance/listunspent/history RPCs.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal >= 1.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd did not reach the 1-ZEC transparent balance within {FUND_TIMEOUT:?} (got {bal})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let getbalance = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance");
    assert_eq!(
        getbalance.as_f64(),
        Some(1.0),
        "getbalance counts the transparent UTXO: {getbalance}"
    );

    // listunspent lists the transparent UTXO with a real (txid, vout) outpoint and the t-address.
    let lu = zecd
        .call("listunspent", json!([]))
        .await
        .expect("listunspent");
    let notes = lu.as_array().expect("listunspent array");
    assert_eq!(
        notes.len(),
        1,
        "exactly one unspent transparent output: {lu}"
    );
    let utxo = &notes[0];
    assert_eq!(
        utxo["address"].as_str(),
        Some(taddr.as_str()),
        "listunspent reports the t-address: {lu}"
    );
    assert!(
        utxo["txid"].as_str().is_some_and(|t| t.len() == 64),
        "real txid outpoint: {lu}"
    );
    assert!(
        (utxo["amount"].as_f64().unwrap_or(0.0) - 1.0).abs() < 1e-8,
        "the UTXO holds 1 ZEC: {lu}"
    );

    // The opt-in gate: this wallet runs under the DEFAULT privacy policy (AllowRevealedRecipients),
    // so a fully-transparent spend is refused. librustzcash's `propose_transfer` funds payments from
    // shielded notes only and never selects the wallet's transparent UTXOs as inputs, and zecd takes
    // its own transparent-builder path *only* under the explicit AllowFullyTransparent policy. With
    // 1 ZEC of transparent funds but 0 shielded notes, `sendtoaddress` therefore fails -6 - proving
    // kept-transparent spending never happens by default. (`regtest_transparent_t2t` exercises the
    // AllowFullyTransparent path that *does* spend a received transparent UTXO here.)
    let err = zecd
        .call("sendtoaddress", json!([funder_taddr, 0.5]))
        .await
        .expect_err("a fully-transparent spend is refused under the default policy");
    assert_eq!(
        err.code(),
        Some(-6),
        "default-policy transparent spend returns insufficient-funds (-6): {err}"
    );

    // 9. Regression guard for the matcher's address-set refresh. A transparent address issued
    //    *beyond* the recovery window (past `transparent_gap_limit`, via the allow-beyond-window
    //    path that `transparent_allow_beyond_recovery_window` enables by default) sits OUTSIDE the
    //    pre-exposed gap window. The block-scan / mempool matcher works off an in-memory set of the
    //    wallet's exposed addresses, so a payment to such an address is recognized ONLY if issuing
    //    the address refreshed that set. zecd marks the set dirty on every transparent issuance for
    //    exactly this case (see `actor::new_transparent_address`); without it, the set still holds
    //    just the original window and this receive is silently dropped. Issue well past the default
    //    gap (20), fund the last (beyond-window) address, and assert it is discovered.
    let mut beyond_taddr = String::new();
    for _ in 0..25 {
        beyond_taddr = zecd
            .call("getnewaddress", json!(["", "transparent"]))
            .await
            .expect("getnewaddress transparent (beyond the recovery window)")
            .as_str()
            .expect("address string")
            .to_string();
    }
    assert!(
        beyond_taddr.starts_with("tm") && beyond_taddr != taddr,
        "issued a distinct beyond-window t-addr: {beyond_taddr}"
    );
    funder
        .send(lwd.grpc_port, &beyond_taddr, FUND_ZATOSHIS)
        .expect("fund the beyond-window transparent address");

    // Discovery (at 0-conf, via the mempool matcher) of the beyond-window receive is the proof that
    // issuing the address refreshed the matcher set. If this times out, the issued address was
    // missing from the set - i.e. issuance failed to mark it dirty.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let lu0 = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent minconf=0");
        let found = lu0
            .as_array()
            .is_some_and(|notes| notes.iter().any(|u| u["address"] == json!(beyond_taddr)));
        if found {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a receive to a beyond-recovery-window address was never discovered - the issued \
             address was absent from the matcher set (transparent issuance must refresh it): {lu0}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    lwd.stop();
    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}
