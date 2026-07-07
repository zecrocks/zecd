//! Ironwood (NU6.3) regtest end-to-end. Two tests:
//!   * `regtest_ironwood_receive_and_orchard_send` - zecd **receives an ironwood note**, then
//!     **spends it** - an ironwood->ironwood send: the wallet's single spendable input is pinned to
//!     the ironwood pool, and past NU6.3 the payment + change route into the ironwood bundle (the
//!     0.3 payment output is verified `pool == "ironwood"`), so the send only broadcasts if zecd's
//!     ironwood proof step ran.
//!   * `regtest_ironwood_sapling_send` - zecd spends a **Sapling** note and produces an **ironwood**
//!     output (a Sapling->ironwood turnstile), starting from a wallet that held no ironwood note.
//!
//! Requires the full ironwood toolchain - the official ironwood zebra RC (`zfnd/zebra:6.0.0-rc.0`),
//! a V6-parsing lightwalletd, an ironwood/regtest-aware `zcash-devtool` funder (its regtest `init`
//! is given `--activation-heights` via [`Funder::init_ironwood`]), and a `zecd` built
//! `--features ironwood` (no `--cfg` needed - upstream exposes the ironwood APIs unconditionally).
//! Gated behind `ZECD_REGTEST_IRONWOOD=1` (its own CI tier) so it never runs against the stock-zebra
//! funded tier - there `Zebrad::start_with_miner_ironwood`'s `"NU6.3"` activation-height key would
//! be rejected at startup.
//!
//! Flow (no `migrate` needed): mine a transparent coinbase to the funder on an NU6.3-active chain,
//! mature it, `shield` into Orchard, then `wallet send` to zecd's unified address. Post-NU6.3 the
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
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// Coinbase blocks mined to the funder up front (see `regtest_funded.rs` for the finalization
/// rationale). The tip ends far past `NU6_3_ACTIVATION_HEIGHT` (8), so NU6.3 is active for the send.
const FUNDER_COINBASES: u32 = 120;
/// Maturity tail mined to a throwaway address after the miner swap, so the funder's coinbases age
/// past the 100-block maturity.
const MATURITY_TAIL: u32 = 130;
/// A throwaway P2SH address that mines the maturity tail (the funder does not control it).
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
/// Generous: lightwalletd ingestion + zecd scan + Orchard/ironwood proving.
const FUND_TIMEOUT: Duration = Duration::from_secs(240);

#[tokio::test]
async fn regtest_ironwood_receive_and_orchard_send() {
    if std::env::var("ZECD_REGTEST_IRONWOOD").is_err() {
        eprintln!(
            "SKIP regtest_ironwood_receive_and_orchard_send: set ZECD_REGTEST_IRONWOOD=1 (plus the \
             ironwood ZEBRAD_BIN/LIGHTWALLETD_BIN/DEVTOOL_BIN and an ironwood-built ZECD_BIN) to run \
             the NU6.3 e2e. The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        panic!(
            "ZECD_REGTEST_IRONWOOD=1 but ZEBRAD_BIN/LIGHTWALLETD_BIN/DEVTOOL_BIN are not all set"
        );
    };

    // 1. Learn the funder's transparent address offline, so zebra mines straight to it (one chain).
    let funder_taddr =
        Funder::derive_transparent_address(&devtool_bin).expect("derive funder transparent addr");

    // 2. Start an NU6.3-active regtest zebra (zakura), mine the funder's coinbases, then restart
    //    mining to a throwaway address and grow a maturity tail. NU6.3 is active from height 8, so
    //    every spend below lands on a V6/ironwood-capable chain.
    let mut zebrad = Zebrad::start_with_miner_ironwood(&zebrad_bin, &funder_taddr)
        .await
        .expect("start ironwood zebrad mining to the funder");
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

    // 3. lightwalletd (V6-aware) in front of zebra, for the funder.
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");

    // 4. Funder shields its matured transparent coinbase into Orchard. The ironwood devtool requires
    //    `init` to carry the regtest `--activation-heights` (matching this chain's NU6.3 height).
    let funder =
        Funder::init_ironwood(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 5. zecd (built --features ironwood) against zebra; get its unified address.
    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against ironwood regtest zebra");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();

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
    funder
        .send(lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS)
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
    // above - keep mining until it confirms into the balance. A `--features ironwood` zecd sums
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
             ZEBRAD_BIN/LIGHTWALLETD_BIN/DEVTOOL_BIN and an ironwood-built ZECD_BIN) to run the \
             NU6.3 e2e. The harness still compiled and linked."
        );
        return;
    }
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        panic!(
            "ZECD_REGTEST_IRONWOOD=1 but ZEBRAD_BIN/LIGHTWALLETD_BIN/DEVTOOL_BIN are not all set"
        );
    };

    // Same NU6.3-active regtest bring-up + funder shield as the receive test.
    let funder_taddr =
        Funder::derive_transparent_address(&devtool_bin).expect("derive funder transparent addr");
    let mut zebrad = Zebrad::start_with_miner_ironwood(&zebrad_bin, &funder_taddr)
        .await
        .expect("start ironwood zebrad mining to the funder");
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
    let funder =
        Funder::init_ironwood(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

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
    funder
        .send(lwd.grpc_port, &sapling_ua, FUND_ZATOSHIS)
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
