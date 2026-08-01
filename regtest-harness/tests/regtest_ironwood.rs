//! Ironwood (NU6.3) regtest end-to-end. Four tests:
//!   * `regtest_ironwood_receive_and_orchard_send` - zecd **receives an ironwood note**, then
//!     **spends it** - an ironwood->ironwood send: the wallet's single spendable input is pinned to
//!     the ironwood pool, and past NU6.3 the payment + change route into the ironwood bundle (the
//!     0.3 payment output is verified `pool == "ironwood"`), so the send only broadcasts if zecd's
//!     ironwood proof step ran.
//!   * `regtest_ironwood_sapling_send` - zecd spends a **Sapling** note and produces an **ironwood**
//!     output (a Sapling->ironwood turnstile), starting from a wallet that held no ironwood note.
//!   * `regtest_ironwood_receive_memo` - the funder attaches a ZIP-302 text memo to a post-NU6.3
//!     send, so zecd receives an **ironwood note carrying a memo**. Proves the Ironwood-domain memo
//!     decryption path (`decrypt_transaction` decrypting the Ironwood bundle) end-to-end: the memo
//!     is surfaced on the received output (`memoStr`/`memo`) on a note asserted `pool == "ironwood"`.
//!   * `regtest_ironwood_self_send_memo_via_block_scan` - ironwood **self-send memo coverage** across
//!     a stop/mine-while-down/respawn: an ironwood self-payment's memo still round-trips on the
//!     receive side after a restart. Coverage, **not** a fix-guard - it is green with and without the
//!     dropped self-send memo cherry-pick (see the test's own doc for the verified why).
//!
//! Requires the full ironwood toolchain: the official ironwood zebra release, Zallet with its
//! Zaino backend configured for regtest NU6.3, and a plain-release `zecd`
//! (ironwood is compiled unconditionally now - no cargo feature) with `ZECD_REGTEST_NU63_HEIGHT=8`
//! in its environment so NU6.3 activates at height 8 on the regtest chain (matching zebra).
//! Gated behind `ZECD_REGTEST_IRONWOOD=1` (its own CI tier) so it never runs against the stock-zebra
//! funded tier.
//!
//! Flow (no `migrate` needed): mine shielded coinbase to the funder on an NU6.3-active chain,
//! mature it, then send to zecd's unified address. Post-NU6.3 the
//! proposal builder auto-routes the Orchard payment to an **ironwood** output (the
//! `orchard_outputs_to_ironwood` path), so zecd scans an ironwood (V3) note at its Orchard receiver.
//!
//! Asserts both that the note is labelled ironwood (`listunspent`'s `pool == "ironwood"`, sourced
//! from `v_tx_outputs.output_pool` = 4) and that its value lands in `getbalance`. The build-time
//! receive wiring (sync/treestate/subtrees/compact-actions) is unit-green; this is the live
//! integration proof and is expected to need timing iteration on the docker stack.

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, start_funder, DEFAULT_MINER_ADDRESS, FOREIGN_TADDR,
    regtest_nuparams, Zebrad, Zecd, ZecdConfig,
};

/// Coinbase blocks mined to the funder up front (see `regtest_funded.rs` for the finalization
/// rationale). The tip ends far past `NU6_3_ACTIVATION_HEIGHT` (8), so NU6.3 is active for the send.
const FUNDER_COINBASES: u32 = 120;
/// Maturity tail mined to a throwaway address after the miner swap, so the funder's coinbases age
/// past the 100-block maturity.
const MATURITY_TAIL: u32 = 130;
/// A throwaway P2SH address that mines the maturity tail (the funder does not control it).
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
/// Generous: zallet sync + zecd scan + Orchard/ironwood proving.
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_ironwood_receive_and_orchard_send() {
    if std::env::var("ZECD_REGTEST_IRONWOOD").is_err() {
        eprintln!(
            "SKIP regtest_ironwood_receive_and_orchard_send: set ZECD_REGTEST_IRONWOOD=1 (plus the \
             ironwood ZEBRAD_BIN/ZALLET_BIN and an ironwood-built ZECD_BIN) to run \
             the NU6.3 e2e. The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(zallet_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("ZALLET_BIN"),
    ) else {
        panic!(
            "ZECD_REGTEST_IRONWOOD=1 but ZEBRAD_BIN/ZALLET_BIN are not all set"
        );
    };

    // 1. Start an NU6.3-active regtest zebra (throwaway miner) and the zallet funder. Zebra 6.x's
    //    `generatetoaddress` mines shielded coinbase (Ironwood post-NU6.3) directly to the funder's
    //    UA — no transparent coinbase, no shield step, no lightwalletd.
    let zebrad = Zebrad::start_ironwood(&zebrad_bin)
        .await
        .expect("start ironwood zebrad");
    zebrad.bootstrap_zallet().await.expect("bootstrap Zallet sync");
    let funder = start_funder(
        &zallet_bin,
        zebrad.rpc_port,
        pick_port().expect("pick zallet rpc port"),
        &regtest_nuparams(true),
    )
    .await
    .expect("start zallet funder");
    zebrad
        .generatetoaddress(FUNDER_COINBASES, &funder.ua)
        .await
        .expect("mine shielded coinbase to funder");
    zebrad
        .generatetoaddress(MATURITY_TAIL, DEFAULT_MINER_ADDRESS)
        .await
        .expect("mine maturity tail");
    funder
        .rpc
        .wait_for_account_balance(&funder.account_uuid, FUND_ZATOSHIS, Duration::from_secs(120))
        .await
        .expect("wait for funder to see shielded coinbase");
    let _funder_taddr = FOREIGN_TADDR.to_string();

    // 5. zecd (ironwood compiled unconditionally) against zebra; get its unified address.
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against ironwood regtest zebra");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();
    // `getnewaddress` must NEVER return an empty response, and must stay a valid unified address
    // even with NU6.3/ironwood active on this chain and an Orchard-only receiver config: ironwood
    // has no distinct UA receiver (it reuses the Orchard receiver - a post-NU6.3 Orchard-address
    // output is simply an ironwood V3 *note*), so the address derives from the account UFVK exactly
    // as it does pre-NU6.3. A `None`/failed derivation would surface as a JSON-RPC *error*, never an
    // empty success string. Assert it here so a regression fails at the call with a clear message
    // rather than later as a downstream funding timeout. (`u`/`utest`/`uregtest` all start with `u`.)
    assert!(
        !zecd_ua.is_empty(),
        "getnewaddress returned an empty address on an NU6.3-active chain (Orchard-only config)"
    );
    assert!(
        zecd_ua.starts_with('u'),
        "getnewaddress returned a non-unified address on an NU6.3-active chain: {zecd_ua:?}"
    );

    // 6. Wait until zecd is fully caught up.
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
            "zecd never reached conn_state ready before funding: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 7. Fund zecd. Post-NU6.3 the funder's `wallet send` auto-routes the Orchard payment to an
    //    ironwood output (no `migrate` needed), so zecd should receive an ironwood note at its
    //    Orchard receiver.
    funder.rpc
        .z_sendmany_and_wait(&funder.ua, &zecd_ua, FUND_ZATOSHIS, None)
        .await
        .expect("send funds to zecd (auto-routed to ironwood post-NU6.3)");
    zebrad
        .generate_blocks(6)
        .await
        .expect("confirm funding send");

    // 8. zecd scans the ironwood note: its value lands in `getbalance` and `listunspent` labels it
    //    `pool == "ironwood"` (sourced from `v_tx_outputs.output_pool` = 4). We poll listunspent at
    //    minconf 0 and mine until the ironwood entry appears, then cross-check the balance.
    let expected = FUND_ZATOSHIS as f64 / 1e8;
    let deadline = Instant::now() + FUND_TIMEOUT;
    let ironwood_note = loop {
        let unspent = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent");
        if let Some(note) = unspent
            .as_array()
            .expect("listunspent array")
            .iter()
            .find(|u| u["pool"] == "ironwood")
            .cloned()
        {
            break note;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never recorded an ironwood note; listunspent = {unspent}"
        );
        // Advance the chain so the receive confirms (relabels from orchard to ironwood once mined)
        // and the actor re-syncs.
        zebrad.generate_blocks(2).await.expect("advance chain");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    assert_eq!(
        ironwood_note["pool"],
        json!("ironwood"),
        "received note is in the ironwood pool: {ironwood_note}"
    );
    assert!(
        ironwood_note["amount"].as_f64().unwrap_or(0.0) > 0.0,
        "ironwood note carries value: {ironwood_note}"
    );

    // The balance eventually reflects the ironwood receive once the note clears the confirmation
    // policy. A foreign (received) note isn't spendable until `untrusted_confirmations` (ZIP-315:
    // 10), so `getbalance` reads 0 right after the note first appears at 0-conf in `listunspent`
    // above - keep mining until it confirms into the balance. A zecd (ironwood always compiled) sums
    // `ironwood_balance()`, and the note is a V3 output `orchard_balance()` excludes, so a non-zero
    // balance here is the ironwood value.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let balance = zecd
            .call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64()
            .unwrap_or(0.0);
        if balance >= expected - 0.001 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "getbalance never reflected the ironwood receive (got {balance}, want ~{expected})"
        );
        zebrad
            .generate_blocks(2)
            .await
            .expect("advance chain to confirm the receive");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // 9. Orchard->Ironwood SEND. zecd now holds an ironwood (Orchard-pool V3) note. Spending it on
    //    this post-NU6.3 chain necessarily builds a V6 transaction whose Orchard payment + change
    //    land in the **ironwood** bundle (new Orchard V2 outputs are forbidden past NU6.3), so the
    //    send can only prove and broadcast if zecd's ironwood proof step (`create_ironwood_proof`
    //    with the `PostNu6_3` circuit) ran. A fresh Orchard receiver is the payee (ironwood shares
    //    the Orchard receiver - there is no distinct ironwood address). The successful broadcast is
    //    the proof the send path works end-to-end; we then confirm it and re-check zecd still holds
    //    ironwood value (the change is an ironwood note too).
    let payee = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress payee")
        .as_str()
        .expect("payee address string")
        .to_string();
    let tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("tip height");
    zecd.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("zecd at tip before the ironwood send");
    // 8b. Pin the SEND INPUT pool. The wallet's entire spendable shielded set is the single ironwood
    //     note funded above - no Orchard V2 or Sapling notes exist - so the send below can only draw
    //     an ironwood input. Assert it explicitly, so this stays a genuine ironwood->ironwood send and
    //     would not silently degrade into an Orchard-V2 drain if the funding/routing ever regressed.
    let pre_send = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent before send");
    let pre_send = pre_send.as_array().expect("listunspent array");
    assert!(
        !pre_send.is_empty(),
        "wallet holds a spendable note before the ironwood send"
    );
    assert!(
        pre_send.iter().all(|u| u["pool"] == "ironwood"),
        "every spendable input before the send is an ironwood note (input pool pinned): {pre_send:?}"
    );
    // A note can read spendable in `getbalance` a confirmation before note selection accepts it, so
    // retry the send (a transient -6) while advancing the chain, exactly as the funded e2e does.
    let deadline = Instant::now() + FUND_TIMEOUT;
    let send_txid = loop {
        match zecd.call("sendtoaddress", json!([payee, 0.3])).await {
            Ok(txid) => break txid.as_str().expect("txid string").to_string(),
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "orchard->ironwood send never succeeded (last error: {e})"
                );
                zebrad
                    .generate_blocks(2)
                    .await
                    .expect("advance chain for spendability");
                let tip = zebrad
                    .rpc("getblockcount", json!([]))
                    .await
                    .expect("getblockcount")
                    .as_u64()
                    .expect("tip height");
                let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    assert_eq!(
        send_txid.len(),
        64,
        "orchard->ironwood send returns a display-hex txid: {send_txid}"
    );

    // Confirm the send and verify it landed: it shows as an outgoing tx, and zecd still holds an
    // ironwood note (the change - proof the V6/ironwood output side round-tripped through the scan).
    zebrad
        .generate_blocks(6)
        .await
        .expect("confirm the ironwood send");
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .expect("tip height");
        let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;
        let txs = zecd
            .call("listtransactions", json!([]))
            .await
            .expect("listtransactions");
        let sent = txs
            .as_array()
            .expect("listtransactions array")
            .iter()
            .any(|t| t["category"] == "send");
        let unspent = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent");
        let unspent = unspent.as_array().expect("listunspent array");
        // Change side: the wallet still holds ironwood value after the send.
        let has_ironwood = unspent.iter().any(|u| u["pool"] == "ironwood");
        // Payment side: the 0.3 note paid to `payee` (a self-owned Orchard receiver) landed as an
        // ironwood note. This is the recipient half of the ironwood->ironwood send - the fee is drawn
        // from the change, so the payment output is exactly 0.3 and distinct from the ~0.7 change.
        let has_ironwood_payment = unspent.iter().any(|u| {
            u["pool"] == "ironwood" && (u["amount"].as_f64().unwrap_or(0.0) - 0.3).abs() < 0.001
        });
        if sent && has_ironwood && has_ironwood_payment {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ironwood send never confirmed as an outgoing tx with an ironwood payment + change; \
             listtransactions send={sent}, has ironwood={has_ironwood}, \
             has ironwood 0.3 payment={has_ironwood_payment}"
        );
        zebrad
            .generate_blocks(2)
            .await
            .expect("advance chain to confirm the send");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // 10. Anchor-retention regression guard (librustzcash#2554). On a post-NU6.3 chain, whenever the
    //     scanner processes a batch whose starting `from_state` height (or a checkpoint height within
    //     it) is a multiple of `ANCHOR_RETENTION_INTERVAL` (288), the ironwood shardtree retains that
    //     checkpoint as a durable anchor - an `add_retained_checkpoint` write into the
    //     `ironwood_tree_retained_checkpoints` table. That table did not exist before #2554 (only the
    //     Sapling/Orchard counterparts did), so scanning across a 288-boundary failed the whole batch
    //     with `no such table: ironwood_tree_retained_checkpoints`. Every regtest chain here otherwise
    //     tops out below 288, so this is the one place that drives zecd's scan across the boundary:
    //     sync exactly to height 288, then scan block 289 on its own - its batch `from_state` is height
    //     288 (a 288-multiple), so `update_tree` retains the ironwood anchor at 288 regardless of
    //     shielded activity in that block. Without #2554 the scan wedges and `wait_until_synced` times
    //     out; with it, zecd scans cleanly across the interval.
    const ANCHOR_RETENTION_INTERVAL: u64 = 288;
    let pre_tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("tip height");
    assert!(
        pre_tip < ANCHOR_RETENTION_INTERVAL,
        "guard assumes the chain sits below the first anchor-retention interval before it runs \
         (tip {pre_tip}); if the earlier flow now exceeds {ANCHOR_RETENTION_INTERVAL}, retarget this \
         to the next multiple"
    );
    // Sync zecd to exactly the interval height, so the following block is scanned in its own batch.
    zebrad
        .generate_blocks((ANCHOR_RETENTION_INTERVAL - pre_tip) as u32)
        .await
        .expect("mine up to the anchor-retention interval");
    zecd.wait_until_synced(ANCHOR_RETENTION_INTERVAL, FUND_TIMEOUT)
        .await
        .expect("zecd syncs up to the anchor-retention interval");
    // One more block: zecd scans it with `from_state` at height 288, retaining the ironwood anchor.
    zebrad
        .generate_blocks(1)
        .await
        .expect("mine one block past the anchor-retention interval");
    zecd.wait_until_synced(ANCHOR_RETENTION_INTERVAL + 1, FUND_TIMEOUT)
        .await
        .expect(
            "zecd scans across the anchor-retention interval without hitting the missing \
             ironwood_tree_retained_checkpoints table (librustzcash#2554)",
        );
    // The boundary range committed: a read RPC still resolves against the scanned wallet.
    zecd.call("getbalance", json!([]))
        .await
        .expect("getbalance after scanning past the anchor-retention interval");
}

/// Sapling->Ironwood send: prove zecd can spend a **Sapling** note and produce an **ironwood** output
/// past NU6.3. The wallet is funded with ONLY a Sapling note (the funder pays zecd's Sapling
/// receiver), so the send's single input pool is Sapling; paying a fresh Orchard receiver on a
/// post-NU6.3 chain routes the output into the ironwood bundle (a Sapling->ironwood turnstile,
/// permitted under the default privacy policy). Because the wallet held no Orchard/ironwood note
/// before the send, any ironwood note afterwards is proof the send itself minted it.
#[tokio::test]
async fn regtest_ironwood_sapling_send() {
    if std::env::var("ZECD_REGTEST_IRONWOOD").is_err() {
        eprintln!(
            "SKIP regtest_ironwood_sapling_send: set ZECD_REGTEST_IRONWOOD=1 (plus the ironwood \
             ZEBRAD_BIN/ZALLET_BIN and an ironwood-built ZECD_BIN) to run the \
             NU6.3 e2e. The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(zallet_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("ZALLET_BIN"),
    ) else {
        panic!(
            "ZECD_REGTEST_IRONWOOD=1 but ZEBRAD_BIN/ZALLET_BIN are not all set"
        );
    };

    // Same NU6.3-active regtest bring-up + zallet funder as the receive test.
    let zebrad = Zebrad::start_ironwood(&zebrad_bin)
        .await
        .expect("start ironwood zebrad");
    zebrad.bootstrap_zallet().await.expect("bootstrap Zallet sync");
    let funder = start_funder(
        &zallet_bin,
        zebrad.rpc_port,
        pick_port().expect("pick zallet rpc port"),
        &regtest_nuparams(true),
    )
    .await
    .expect("start zallet funder");
    zebrad
        .generatetoaddress(FUNDER_COINBASES, &funder.ua)
        .await
        .expect("mine shielded coinbase to funder");
    zebrad
        .generatetoaddress(MATURITY_TAIL, DEFAULT_MINER_ADDRESS)
        .await
        .expect("mine maturity tail");
    funder
        .rpc
        .wait_for_account_balance(&funder.account_uuid, FUND_ZATOSHIS, Duration::from_secs(120))
        .await
        .expect("wait for funder to see shielded coinbase");
    let _funder_taddr = FOREIGN_TADDR.to_string();

    // zecd with BOTH shielded pools enabled, so it can hand out a Sapling receiver and route Orchard
    // outputs (which become ironwood past NU6.3).
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.pools = Some((
        vec!["sapling".into(), "orchard".into()],
        vec!["sapling".into(), "orchard".into()],
    ));
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd with sapling+orchard against ironwood zebra");

    // A Sapling-only receiver for zecd; the funder pays it, so zecd holds exactly one Sapling note.
    let sapling_ua = zecd
        .call("getnewaddress", json!(["", "sapling"]))
        .await
        .expect("getnewaddress sapling")
        .as_str()
        .expect("sapling address string")
        .to_string();

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

    // Fund zecd's Sapling receiver. The funder spends its (ironwood) notes to a Sapling recipient -
    // a cross-pool payment that lands as a plain Sapling note in zecd.
    funder.rpc
        .z_sendmany_and_wait(&funder.ua, &sapling_ua, FUND_ZATOSHIS, None)
        .await
        .expect("fund zecd's Sapling receiver");
    zebrad
        .generate_blocks(6)
        .await
        .expect("confirm sapling funding");

    // Wait until zecd sees a spendable Sapling note and NO ironwood note yet.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let unspent = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent");
        let arr = unspent.as_array().expect("listunspent array");
        let has_sapling = arr.iter().any(|u| u["pool"] == "sapling");
        let has_ironwood = arr.iter().any(|u| u["pool"] == "ironwood");
        assert!(
            !has_ironwood,
            "wallet must hold no ironwood note before the send: {unspent}"
        );
        if has_sapling {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never recorded the Sapling note: {unspent}"
        );
        zebrad.generate_blocks(2).await.expect("advance chain");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Sapling->Ironwood send: pay a fresh Orchard receiver. The only fundable input is the Sapling
    // note, and the Orchard-pool output becomes an ironwood note past NU6.3.
    let payee = zecd
        .call("getnewaddress", json!(["", "orchard"]))
        .await
        .expect("getnewaddress orchard payee")
        .as_str()
        .expect("payee address string")
        .to_string();
    let tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("getblockcount")
        .as_u64()
        .expect("tip height");
    zecd.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("zecd at tip before the sapling->ironwood send");
    let deadline = Instant::now() + FUND_TIMEOUT;
    let send_txid = loop {
        match zecd.call("sendtoaddress", json!([payee, 0.3])).await {
            Ok(txid) => break txid.as_str().expect("txid string").to_string(),
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "sapling->ironwood send never succeeded (last error: {e})"
                );
                zebrad
                    .generate_blocks(2)
                    .await
                    .expect("advance chain for spendability");
                let tip = zebrad
                    .rpc("getblockcount", json!([]))
                    .await
                    .expect("getblockcount")
                    .as_u64()
                    .expect("tip height");
                let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    assert_eq!(
        send_txid.len(),
        64,
        "sapling->ironwood send returns a display-hex txid: {send_txid}"
    );

    // Confirm: the wallet, which held only a Sapling note, now holds an ironwood note - the output
    // the Sapling spend minted past NU6.3.
    zebrad
        .generate_blocks(6)
        .await
        .expect("confirm sapling->ironwood send");
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .expect("tip height");
        let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;
        let unspent = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent");
        if unspent
            .as_array()
            .expect("listunspent array")
            .iter()
            .any(|u| u["pool"] == "ironwood")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the Sapling spend never produced an ironwood output: {unspent}"
        );
        zebrad
            .generate_blocks(2)
            .await
            .expect("advance chain to confirm the send");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Ironwood receive **memo**: the funder attaches a ZIP-302 text memo to a post-NU6.3 send, which
/// auto-routes to an ironwood output, so zecd receives an ironwood note carrying a memo. This is the
/// end-to-end proof of the Ironwood-domain memo decryption path - `decrypt_transaction` decrypting
/// the Ironwood bundle (librustzcash `dw/ironwood-scan-model`, "Decrypt Ironwood outputs with the
/// Ironwood domain"). Compact blocks carry no memos, so surfacing the memo on the *mined* receive
/// exercises that decryption via the mempool full-tx store and/or the enhancement backfill; the
/// existing tier only proved memos for the Orchard/Sapling domains (`regtest_funded.rs`), never the
/// Ironwood one. Asserts the memo (`memoStr` text + `memo` hex) on a note confirmed `pool ==
/// "ironwood"`.
#[tokio::test]
async fn regtest_ironwood_receive_memo() {
    if std::env::var("ZECD_REGTEST_IRONWOOD").is_err() {
        eprintln!(
            "SKIP regtest_ironwood_receive_memo: set ZECD_REGTEST_IRONWOOD=1 (plus the ironwood \
             ZEBRAD_BIN/ZALLET_BIN and an ironwood-built ZECD_BIN) to run the \
             NU6.3 e2e. The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(zallet_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("ZALLET_BIN"),
    ) else {
        panic!(
            "ZECD_REGTEST_IRONWOOD=1 but ZEBRAD_BIN/ZALLET_BIN are not all set"
        );
    };

    /// The ZIP-302 text memo the funder attaches; zecd must surface it on the ironwood receive.
    const RECEIVE_MEMO: &str = "ironwood memo e2e";

    // 1-3. Bring up an NU6.3 chain, start the zallet funder, mine shielded coinbase to it.
    let zebrad = Zebrad::start_ironwood(&zebrad_bin)
        .await
        .expect("start ironwood zebrad");
    zebrad.bootstrap_zallet().await.expect("bootstrap Zallet sync");
    let funder = start_funder(
        &zallet_bin,
        zebrad.rpc_port,
        pick_port().expect("pick zallet rpc port"),
        &regtest_nuparams(true),
    )
    .await
    .expect("start zallet funder");
    zebrad
        .generatetoaddress(FUNDER_COINBASES, &funder.ua)
        .await
        .expect("mine shielded coinbase to funder");
    zebrad
        .generatetoaddress(MATURITY_TAIL, DEFAULT_MINER_ADDRESS)
        .await
        .expect("mine maturity tail");
    funder
        .rpc
        .wait_for_account_balance(&funder.account_uuid, FUND_ZATOSHIS, Duration::from_secs(120))
        .await
        .expect("wait for funder to see shielded coinbase");
    let _funder_taddr = FOREIGN_TADDR.to_string();

    // 5-6. Start zecd (ironwood compiled unconditionally) and wait until it is caught up.
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against ironwood regtest zebra");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();
    // `getnewaddress` must NEVER return an empty response, and must stay a valid unified address
    // even with NU6.3/ironwood active on this chain and an Orchard-only receiver config: ironwood
    // has no distinct UA receiver (it reuses the Orchard receiver - a post-NU6.3 Orchard-address
    // output is simply an ironwood V3 *note*), so the address derives from the account UFVK exactly
    // as it does pre-NU6.3. A `None`/failed derivation would surface as a JSON-RPC *error*, never an
    // empty success string. Assert it here so a regression fails at the call with a clear message
    // rather than later as a downstream funding timeout. (`u`/`utest`/`uregtest` all start with `u`.)
    assert!(
        !zecd_ua.is_empty(),
        "getnewaddress returned an empty address on an NU6.3-active chain (Orchard-only config)"
    );
    assert!(
        zecd_ua.starts_with('u'),
        "getnewaddress returned a non-unified address on an NU6.3-active chain: {zecd_ua:?}"
    );
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
            "zecd never reached conn_state ready before funding: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 7. Fund zecd WITH A MEMO. Post-NU6.3 the funder's `wallet send` auto-routes the Orchard
    //    payment into an ironwood output, so zecd receives an ironwood note carrying the memo.
    funder.rpc
        .z_sendmany_and_wait(&funder.ua, &zecd_ua, FUND_ZATOSHIS, Some(RECEIVE_MEMO))
        .await
        .expect("send funds (with a memo) to zecd (auto-routed to ironwood post-NU6.3)");
    zebrad
        .generate_blocks(6)
        .await
        .expect("confirm the memo funding send");

    // 8. zecd scans the ironwood note and surfaces the memo. Poll (mining to drive confirmation and
    //    any enhancement backfill) until BOTH hold: an ironwood note is present in listunspent, and
    //    the receive in listtransactions decodes the funder's text memo. A memo on the received
    //    ironwood output can only appear if `decrypt_transaction` decrypted the Ironwood bundle.
    let memo_hex: String = RECEIVE_MEMO.bytes().map(|b| format!("{b:02x}")).collect();
    let deadline = Instant::now() + FUND_TIMEOUT;
    let receive = loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .expect("tip height");
        let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;

        let unspent = zecd
            .call("listunspent", json!([0]))
            .await
            .expect("listunspent");
        let has_ironwood = unspent
            .as_array()
            .expect("listunspent array")
            .iter()
            .any(|u| u["pool"] == "ironwood");

        let txs = zecd
            .call("listtransactions", json!([]))
            .await
            .expect("listtransactions");
        let receive = txs
            .as_array()
            .expect("listtransactions array")
            .iter()
            .find(|t| t["category"] == "receive" && t["memoStr"].as_str() == Some(RECEIVE_MEMO));

        if has_ironwood {
            if let Some(receive) = receive {
                break receive.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "zecd never surfaced the ironwood receive with its memo; has_ironwood={has_ironwood}, \
             listtransactions={txs}"
        );
        zebrad
            .generate_blocks(2)
            .await
            .expect("advance chain to confirm / enhance the memo receive");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    // The received ironwood output carries the memo: decoded text in `memoStr`, raw ZIP-302 bytes
    // in `memo` (zcashd's z_viewtransaction field names).
    assert_eq!(
        receive["memoStr"].as_str(),
        Some(RECEIVE_MEMO),
        "the ironwood receive decodes the funder's text memo: {receive}"
    );
    assert_eq!(
        receive["memo"].as_str(),
        Some(memo_hex.as_str()),
        "the ironwood receive carries the memo hex: {receive}"
    );

    // gettransaction on the receive surfaces the same memo on its receive detail.
    let recv_txid = receive["txid"]
        .as_str()
        .expect("the receive carries a txid")
        .to_string();
    let gt_recv = zecd
        .call("gettransaction", json!([recv_txid]))
        .await
        .expect("gettransaction on the ironwood memo receive");
    let recv_detail = gt_recv["details"]
        .as_array()
        .expect("gettransaction details")
        .iter()
        .find(|d| d["category"] == "receive")
        .cloned()
        .unwrap_or_else(|| panic!("gettransaction details carry the receive: {gt_recv}"));
    assert_eq!(
        recv_detail["memoStr"].as_str(),
        Some(RECEIVE_MEMO),
        "gettransaction's ironwood receive detail decodes the memo: {recv_detail}"
    );
}

/// Ironwood **self-send memo coverage** across a stop/restart: send a memo to one of the wallet's
/// own ironwood addresses, tear zecd down, mine while it is down, respawn on the same datadir, and
/// assert the receive side still surfaces the memo (`memoStr`/`memo`) on `gettransaction`.
///
/// NB - this is *coverage*, not a fix-guard. It was written to prove that upstream's
/// `zcash_client_sqlite` **needs** the dropped "Backfill received-note memos for own self-sends"
/// cherry-pick; PR #136 (this exact test on fix-less upstream) proved it does **not** - the test is
/// green with *and* without that cherry-pick, so the fix is redundant for zecd's flow and was
/// abandoned rather than upstreamed. The reason it survives, verified by reading upstream:
///   * A shielded self-payment is a `Recipient::External` (external OVK): no received note exists at
///     send time; only a `sent_notes` row carries the memo. The compact-block scan later materialises
///     the received note with a **NULL** memo, and `queue_tx_retrieval` classifies the wallet's own
///     (raw-pre-stored) txs `Status`, so enhancement never re-decrypts them. `v_received_outputs.memo`
///     is the received note's own memo with no coalesce from the linked sent note.
///   * So the received-note memo is filled only by `decrypt_and_store_transaction` on the *full* tx -
///     which zecd does via the **mempool 0-conf path** (`store_mempool_tx`) in normal operation, and
///     via **enhancement** on a from-seed restore (fresh DB → no pre-stored raw → an `Enhancement`
///     request, not `Status`). The dropped `put_blocks` backfill only ever covered the residual case
///     of an *authoring* node whose mempool never saw its own self-send *and* is never restored -
///     genuinely narrow and self-healing (a rescan/restore fixes it).
///
/// This test's stop → mine-while-down → respawn does *not* reliably isolate that residual case (the
/// mempool/decrypt paths still fill the memo), which is exactly why it stays green here. It is kept
/// as end-to-end proof that an ironwood self-send memo round-trips across a restart; post-NU6.3 every
/// self-payment lands in the Ironwood bundle, so it exercises the Ironwood-domain decrypt path.
#[tokio::test]
async fn regtest_ironwood_self_send_memo_via_block_scan() {
    if std::env::var("ZECD_REGTEST_IRONWOOD").is_err() {
        eprintln!(
            "SKIP regtest_ironwood_self_send_memo_via_block_scan: set ZECD_REGTEST_IRONWOOD=1 (plus \
             the ironwood ZEBRAD_BIN/ZALLET_BIN and an ironwood-built ZECD_BIN) to run \
             the NU6.3 e2e. The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(zallet_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("ZALLET_BIN"),
    ) else {
        panic!(
            "ZECD_REGTEST_IRONWOOD=1 but ZEBRAD_BIN/ZALLET_BIN are not all set"
        );
    };

    /// The ZIP-302 text memo zecd attaches to its own self-send; asserted on the received side
    /// after the restart, under this test's mempool-denied timing.
    const SELF_MEMO: &str = "ironwood self-send memo";
    /// Hex of `SELF_MEMO`, as `sendtoaddress`'s trailing memo argument wants it.
    const SELF_MEMO_HEX: &str = "69726f6e776f6f642073656c662d73656e64206d656d6f";
    /// The self-send value (ZEC). Comfortably below the funded 1 ZEC note minus the ZIP-317 fee.
    const SELF_SEND_ZEC: f64 = 0.3;

    // 1. Bring up an NU6.3 chain and the zallet funder (identical to the other ironwood tests).
    let zebrad = Zebrad::start_ironwood(&zebrad_bin)
        .await
        .expect("start ironwood zebrad");
    zebrad.bootstrap_zallet().await.expect("bootstrap Zallet sync");
    let funder = start_funder(
        &zallet_bin,
        zebrad.rpc_port,
        pick_port().expect("pick zallet rpc port"),
        &regtest_nuparams(true),
    )
    .await
    .expect("start zallet funder");
    zebrad
        .generatetoaddress(FUNDER_COINBASES, &funder.ua)
        .await
        .expect("mine shielded coinbase to funder");
    zebrad
        .generatetoaddress(MATURITY_TAIL, DEFAULT_MINER_ADDRESS)
        .await
        .expect("mine maturity tail");
    funder
        .rpc
        .wait_for_account_balance(&funder.account_uuid, FUND_ZATOSHIS, Duration::from_secs(120))
        .await
        .expect("wait for funder to see shielded coinbase");

    // 5. Start zecd and wait until it reports a ready upstream.
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let mut zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against ironwood regtest zebra");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("address string")
        .to_string();
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
            "zecd never reached conn_state ready before funding: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 6. Fund zecd with an ironwood note and mine until it is *spendable* (a received/untrusted note
    //    needs `untrusted_confirmations` - ZIP-315: 10 - before `getbalance` counts it).
    funder
        .rpc
        .z_sendmany_and_wait(&funder.ua, &zecd_ua, FUND_ZATOSHIS, None)
        .await
        .expect("fund zecd (auto-routed to ironwood post-NU6.3)");
    zebrad
        .generate_blocks(6)
        .await
        .expect("confirm the funding");
    let want_spendable = (FUND_ZATOSHIS as f64) / 1e8 - 0.01;
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .expect("tip height");
        let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;
        let balance = zecd
            .call("getbalance", json!([]))
            .await
            .expect("getbalance")
            .as_f64()
            .expect("balance number");
        if balance >= want_spendable {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "zecd's ironwood note never became spendable (balance {balance}, want ~{want_spendable})"
        );
        zebrad
            .generate_blocks(2)
            .await
            .expect("advance chain to make the note spendable");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // 7. zecd self-sends to a fresh OWN address, carrying a memo. `sendtoaddress`'s trailing memo
    //    argument (after Bitcoin Core's comment/comment_to and the unused fee/verbose slots) rides
    //    the same positional shape as `regtest_funded.rs`. The send stores its raw bytes and
    //    broadcasts; post-NU6.3 the payment routes into the Ironwood bundle.
    let self_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress for the self-send")
        .as_str()
        .expect("self address string")
        .to_string();
    let self_txid = zecd
        .call(
            "sendtoaddress",
            json!([
                self_ua,
                SELF_SEND_ZEC,
                "",
                "",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                SELF_MEMO_HEX
            ]),
        )
        .await
        .expect("ironwood self-send succeeds")
        .as_str()
        .expect("self-send txid")
        .to_string();

    // 8. Deny the mempool path: tear zecd down *immediately* (no awaits between the send and the
    //    stop, so its ~2s poller has no chance to decrypt-and-store the still-unmined self-send),
    //    keeping the datadir - and its pre-stored raw for `self_txid` - intact.
    zecd.stop_keeping_datadir()
        .await
        .expect("stop zecd, keeping its datadir");

    // 9. Mine the self-send WHILE zecd is down, so the tx is confirmed and gone from the mempool
    //    before zecd runs again - it can now be discovered only by scanning the mined block.
    zebrad
        .generate_blocks(6)
        .await
        .expect("mine + confirm the self-send while zecd is stopped");

    // 10. Respawn on the same datadir. zecd rescans the block carrying the self-send: the compact
    //     scan materialises the received note NULL-memo, and - the raw tx being pre-stored from the
    //     send - `queue_tx_retrieval` classifies it `Status`, so enhancement does not re-decrypt it.
    //     The memo nevertheless lands (see this test's doc), which is what step 11 asserts.
    zecd.respawn()
        .await
        .expect("respawn zecd on the kept datadir");

    // 11. Poll until zecd surfaces the self-send's receive side WITH its memo. Advancing the chain
    //     drives the scan forward; the tx is already mined, so nothing here re-introduces it to the
    //     mempool. A timeout means an ironwood self-send's memo stopped reaching the receive side
    //     across a restart - the coverage this test provides.
    let deadline = Instant::now() + FUND_TIMEOUT;
    let recv_detail = loop {
        let tip = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .expect("tip height");
        let _ = zecd.wait_until_synced(tip, FUND_TIMEOUT).await;

        let gt = zecd
            .call("gettransaction", json!([self_txid]))
            .await
            .expect("gettransaction on the self-send");
        let recv = gt["details"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|d| d["category"] == "receive" && d["memoStr"].as_str() == Some(SELF_MEMO))
            .cloned();
        if let Some(recv) = recv {
            break recv;
        }
        assert!(
            Instant::now() < deadline,
            "zecd never surfaced the self-send's receive memo after the restart: {gt}"
        );
        zebrad
            .generate_blocks(2)
            .await
            .expect("advance chain to drive the scan");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    // The self-send's received output is to our own address and carries both memo encodings -
    // decoded text in `memoStr`, raw ZIP-302 bytes in `memo` - after a restart across the mining.
    assert_eq!(
        recv_detail["address"].as_str(),
        Some(self_ua.as_str()),
        "the self-send receive is to our own address: {recv_detail}"
    );
    assert_eq!(
        recv_detail["memoStr"].as_str(),
        Some(SELF_MEMO),
        "the self-send receive decodes its memo after the restart: {recv_detail}"
    );
    assert_eq!(
        recv_detail["memo"].as_str(),
        Some(SELF_MEMO_HEX),
        "the self-send receive carries the memo hex after the restart: {recv_detail}"
    );
}
