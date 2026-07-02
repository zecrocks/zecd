//! Funded regtest end-to-end: get real Orchard funds into `zecd` and verify it sees them.
//!
//! Regtest can't mine a coinbase directly into an Orchard note that `zecd` (Orchard-only receive)
//! would scan, so we fund it the way the protocol allows: mine a **transparent** coinbase to a
//! funding wallet (`zcash-devtool`), let it mature (100 blocks), **shield** it into Orchard, then
//! **send** Orchard funds to `zecd`'s unified address.
//!
//! Everything runs on a **single chain**: we derive the funder's transparent address *offline*
//! (`devtool wallet derive-address`) and mine straight to it, so the funder's wallet birthday
//! anchor is taken from the same chain it spends on (a throwaway "discover the address" chain would
//! hand the wallet a wrong note-commitment anchor and the shield/send proofs would be invalid).
//!
//! Skips cleanly unless `ZEBRAD_BIN`, `LIGHTWALLETD_BIN` and `DEVTOOL_BIN` are all set (see
//! README.md).
//!
//! Phase 1: funded receive (funder → zecd) - first observed at **0 conf via the mempool
//! stream** (`getunconfirmedbalance`/`listtransactions`/`listunspent minconf=0`), then
//! confirmed (balance + history). Phase 2: zecd *spends* - the walletlock/-13/walletpassphrase
//! gate, a real `sendtoaddress` back to the funder with `gettransaction` shape checks through
//! confirmation, and the payment-poller methods (`listsinceblock` cursor loop,
//! `getreceivedbyaddress`/`listreceivedbyaddress`). Phase 3: a send during an upstream outage
//! (committed-send contract), with the health endpoints (`/healthz` `/readyz` `/status`)
//! checked through the outage and the recovery. Phase 4: a second confirmed send. Then a
//! concurrent-send burst proving the no-double-spend invariant (exactly one winner, losers
//! get -6, and `getrpcinfo.active_commands` shows the burst in flight). Phase 6: a 2-output
//! `sendmany` (shielded + transparent recipient). Phase 7: `sendrawtransaction`'s
//! accept/idempotency contract. Phase 8: a **self-send** (pay our own address) carrying a
//! memo - surfaced as a send+receive pair in `gettransaction`/`listtransactions`/
//! `z_listtransactions` (librustzcash flags self-payments `is_change`, so zecd must key off the
//! external recipient scope, not `is_change`, to keep them - and their memos - visible).
//! Finally `scripts/conformance.py` runs against the live funded daemon, putting its full
//! Bitcoin-Core wire-format suite under CI.
//!
//! (Tx expiry/abandonment and manual delivery of an *unbroadcast* tx need the broadcast path
//! down while the chain keeps advancing - two roles a single local zebra node can't separate -
//! so they're covered by unit tests, not this zebra-only e2e.)

use std::time::{Duration, Instant};

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, resolve_bin, Funder, Lightwalletd, Zebrad, Zecd, ZecdConfig,
};

/// Coinbase blocks mined to the funder up front. zebra finalizes blocks deeper than
/// `MAX_BLOCK_REORG_HEIGHT` (= coinbase maturity − 1 = 99) below the tip; only finalized blocks are
/// persisted to disk and survive the miner-swap restart below. So mining 120 finalizes the
/// funder's coinbases at heights ~1..21 (the rest are non-finalized and dropped on restart). This
/// matters because the light-client coinbase-maturity filter can't recognise coinbase-ness for
/// outputs discovered via lightwalletd's GetAddressUtxos (no tx_index), so the funder must simply
/// never hold an immature coinbase - the restart drops the immature (non-finalized) tail.
const FUNDER_COINBASES: u32 = 120;
/// After restarting mining to a throwaway address, mine this many blocks. The restart resets the
/// tip to the finalized height (~21); this tail re-grows the chain so the surviving funder
/// coinbases (~1..21) are well past the 100-block maturity, and gives the funder a recent tip to
/// build its shield against. Comfortably exceeds coinbase maturity (100).
const MATURITY_TAIL: u32 = 130;
/// A throwaway P2SH address that mines the maturity tail (the funder does not control it).
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
/// 1 ZEC, in zatoshis.
const FUND_ZATOSHIS: u64 = 100_000_000;
/// ZIP-302 text memo the funder attaches to the funding send, so zecd's receive-memo path is
/// exercised. Decoded text is asserted against `memoStr`; hex against `memo`.
const RECEIVE_MEMO: &str = "hello from the funder";
/// Generous: lightwalletd ingestion + zecd scan + Orchard proving.
const FUND_TIMEOUT: Duration = Duration::from_secs(240);
/// Passphrase the funded wallet is created with (`init --encrypt`). Drives the locked-send
/// gate before Phase 2 and conformance.py's lock/unlock state machine at the end. ≥12 chars
/// to satisfy the wallet-passphrase minimum.
const ENCRYPT_PASSPHRASE: &str = "regtest-pass";

#[tokio::test]
async fn regtest_funded_orchard_receive() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!(
            "SKIP regtest_funded_orchard_receive: set ZEBRAD_BIN, LIGHTWALLETD_BIN and DEVTOOL_BIN \
             to run the funded e2e (see README.md). The harness still compiled and linked."
        );
        return;
    };

    // 1. Learn the funder's transparent address offline (no chain yet) so zebra can mine its
    //    coinbase straight to it - keeping the whole flow on one chain.
    let funder_taddr = Funder::derive_transparent_address(&devtool_bin)
        .expect("derive funder transparent address");

    // 2. Single chain: zebra first mines a few coinbases straight to the funder, then restarts
    //    mining to a throwaway address. This keeps everything on one chain while letting the
    //    funder's coinbases age past maturity without it accruing new, immature ones.
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

    // 3. lightwalletd in front of zebra (ingests the whole chain).
    let lwd = Lightwalletd::start(&lwd_bin, zebrad.rpc_port)
        .await
        .expect("start lightwalletd");

    // 4. Initialise the funder against THIS chain, then shield its now-mature transparent coinbases
    //    into Orchard. Every coinbase the funder holds is older than the maturity tail, so the
    //    broadcast is accepted.
    let funder = Funder::init(&devtool_bin, lwd.grpc_port).expect("initialise funding wallet");
    funder.sync(lwd.grpc_port).expect("funder sync (coinbase)");
    funder
        .shield(lwd.grpc_port)
        .expect("shield transparent coinbase into Orchard");
    // The shielded note must reach the default confirmation depth (3 for trusted/self-shielded
    // notes) before the funder can spend it; a few extra blocks cover the tip skew.
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync (shielded)");

    // 5. zecd against zebra's JSON-RPC; get its Orchard unified address. The wallet is
    // created passphrase-encrypted (`init --encrypt`), so it starts locked - Phase 1 receiving
    // still works (scanning needs only viewing keys), and Phase 2 exercises the unlock gate.
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.encrypt_passphrase = Some(ENCRYPT_PASSPHRASE.to_string());
    // Run this comprehensive send suite through the off-actor proving pipeline (`[spend]
    // pipeline_proving`): this wallet is Orchard-only with the cached proving key, so the pipeline
    // engages, and every send below (sendtoaddress/sendmany/z_sendmany, the self-send, the
    // concurrent burst, the send-during-outage) becomes correctness coverage for it on every PR
    // run. The inline PCZT path stays covered by regtest_proving_cache, the fused path by
    // regtest_sapling, so all three send paths are exercised across the funded tier.
    cfg.pipeline_proving = Some(true);
    let mut zecd = Zecd::start(&cfg)
        .await
        .expect("start zecd against regtest zebra");
    let zecd_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress");
    let zecd_ua = zecd_ua.as_str().expect("address string").to_string();
    assert!(
        zecd_ua.starts_with("uregtest1"),
        "expected a uregtest1 address, got {zecd_ua}"
    );

    // 6. Fund zecd: send Orchard funds from the funder to zecd's UA. First wait for zecd to
    //    be fully caught up (conn_state "ready"): only a caught-up actor subscribes to
    //    lightwalletd's mempool stream, which the 0-conf check below exercises.
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
    // One sync interval of slack so the caught-up pass has opened the mempool stream.
    tokio::time::sleep(Duration::from_secs(3)).await;
    // The funding send carries a ZIP-302 text memo so the *receive*-memo path is exercised
    // end to end: zecd must surface this memo on the received output (`memoStr`). This is the
    // complement to the send-memo coverage in Phase 2 (zecd → funder).
    funder
        .send_with_memo(lwd.grpc_port, &zecd_ua, FUND_ZATOSHIS, Some(RECEIVE_MEMO))
        .expect("send Orchard funds (with a memo) to zecd");

    // 0-conf visibility via the mempool stream: before any block confirms the funding tx,
    // zecd trial-decrypts it out of the mempool and reports it bitcoind-style in
    // getunconfirmedbalance, listtransactions, and listunspent minconf=0.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let pending = zecd
            .call("getunconfirmedbalance", json!([]))
            .await
            .expect("getunconfirmedbalance")
            .as_f64()
            .unwrap_or(0.0);
        if pending > 0.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the funding tx never appeared at 0 conf (mempool stream)"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let txs = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let unconfirmed_receive = txs
        .as_array()
        .expect("array")
        .iter()
        .find(|t| t["category"] == "receive" && t["confirmations"].as_i64() == Some(0));
    assert!(
        unconfirmed_receive.is_some(),
        "the unconfirmed receive rides in listtransactions: {txs}"
    );
    // This foreign receive has no block time and no librustzcash `created` time, so a non-zero
    // `time`/`timereceived` can only come from the actor's transient in-memory first-seen stamp
    // (set when the mempool stream stored the tx). Proves first-seen survives the move off the
    // removed labels.sqlite into the in-memory map (zecd stays stateless: it's never persisted).
    let rcv = unconfirmed_receive.unwrap();
    assert!(
        rcv["time"].as_i64().is_some_and(|t| t > 0) && rcv["time"] == rcv["timereceived"],
        "the 0-conf receive carries an in-memory first-seen time: {rcv}"
    );
    let lu = zecd
        .call("listunspent", json!([0]))
        .await
        .expect("listunspent minconf=0");
    assert!(
        lu.as_array()
            .expect("array")
            .iter()
            .any(|u| u["confirmations"].as_i64() == Some(0)),
        "listunspent minconf=0 lists the unconfirmed note: {lu}"
    );

    // Confirm the funding send. zecd's getbalance uses the default confirmations policy,
    // under which an externally-received (untrusted) note needs 10 confirmations before it
    // counts; mine a couple extra for the tip skew.
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm funding send");

    // 7. zecd scans the note and reports the balance.
    let deadline = Instant::now() + FUND_TIMEOUT;
    let balance = loop {
        let bal = zecd
            .call("getbalance", json!([]))
            .await
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        if bal > 0.0 {
            break bal;
        }
        if Instant::now() >= deadline {
            panic!("zecd did not see the funded Orchard note within {FUND_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    assert!(
        balance > 0.0,
        "zecd should have a positive Orchard balance, got {balance}"
    );

    // The receive shows up in history as a `receive` transaction.
    let txs = zecd
        .call("listtransactions", json!([]))
        .await
        .expect("listtransactions");
    let txs = txs.as_array().expect("listtransactions is an array");
    assert!(
        !txs.is_empty(),
        "expected at least one transaction in zecd history"
    );
    let receive = txs
        .iter()
        .find(|t| t.get("category").and_then(|c| c.as_str()) == Some("receive"))
        .unwrap_or_else(|| panic!("expected a receive in zecd history: {txs:?}"));
    // Receiving a memo: the funder attached RECEIVE_MEMO, so the received output carries it
    // (decoded text in memoStr, raw ZIP-302 bytes in memo) - zcashd's z_viewtransaction names.
    assert_eq!(
        receive["memoStr"].as_str(),
        Some(RECEIVE_MEMO),
        "the received output decodes the funder's text memo: {receive}"
    );
    let memo_hex: String = RECEIVE_MEMO.bytes().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        receive["memo"].as_str(),
        Some(memo_hex.as_str()),
        "the received output carries the memo hex: {receive}"
    );
    let recv_txid = receive["txid"]
        .as_str()
        .expect("the receive carries a txid")
        .to_string();
    // gettransaction on the receive surfaces the same memo on its receive detail.
    let gt_recv = zecd
        .call("gettransaction", json!([recv_txid]))
        .await
        .expect("gettransaction on the funded receive");
    let recv_detail = gt_recv["details"]
        .as_array()
        .expect("details")
        .iter()
        .find(|d| d["category"] == "receive")
        .cloned()
        .unwrap_or_else(|| panic!("gettransaction details carry the receive: {gt_recv}"));
    assert_eq!(
        recv_detail["memoStr"].as_str(),
        Some(RECEIVE_MEMO),
        "gettransaction's receive detail decodes the memo: {recv_detail}"
    );
    // A pure receive reports `amount` == exactly what arrived (fee-exclusive) and carries no
    // top-level `fee` - like bitcoind, where `fee` appears only on txs the wallet sent.
    // librustzcash records a fee for every fully-shielded tx (derived from the public value
    // balance, even for a tx the wallet never paid for); this asserts zecd does not fold that
    // phantom fee into the deposit amount or expose it.
    assert_eq!(
        gt_recv["amount"].as_f64(),
        Some(FUND_ZATOSHIS as f64 / 100_000_000.0),
        "gettransaction.amount on a pure receive equals what arrived, fee excluded: {gt_recv}"
    );
    assert!(
        gt_recv.get("fee").is_none(),
        "a pure receive carries no top-level fee field: {gt_recv}"
    );

    // ---- Phase 2: zecd spends ----

    // The poller methods credit the funded receive. getreceivedbyaddress: exactly the 1 ZEC
    // sent to our UA; listreceivedbyaddress lists the UA with the contributing txid.
    let recv = zecd
        .call("getreceivedbyaddress", json!([zecd_ua]))
        .await
        .expect("getreceivedbyaddress");
    assert_eq!(
        recv.as_f64(),
        Some(1.0),
        "the 1-ZEC funding receive is credited to the UA, got {recv}"
    );
    let lra = zecd
        .call("listreceivedbyaddress", json!([1, false]))
        .await
        .expect("listreceivedbyaddress");
    assert!(
        lra.as_array().expect("array").iter().any(|e| {
            e["address"] == json!(zecd_ua.as_str())
                && e["txids"].as_array().is_some_and(|t| !t.is_empty())
        }),
        "listreceivedbyaddress lists the funded UA with its txid: {lra}"
    );

    // Capture the listsinceblock cursor before the send, exactly as a payment poller would.
    let lsb = zecd
        .call("listsinceblock", json!([]))
        .await
        .expect("listsinceblock");
    let cursor = lsb["lastblock"]
        .as_str()
        .expect("lastblock hash")
        .to_string();
    assert_eq!(cursor.len(), 64, "lastblock is a block hash: {lsb}");

    let funder_ua = funder.unified_address().expect("funder unified address");

    // The wallet was created encrypted (`init --encrypt`), so it starts locked: a real spend is
    // refused (-13; the seed check precedes input selection, so the funds don't matter), a wrong
    // passphrase is rejected (-14), and the configured passphrase unlocks it with a timeout long
    // enough to cover the remaining phases.
    let err = zecd
        .call("sendtoaddress", json!([funder_ua, 0.4]))
        .await
        .expect_err("a locked wallet must refuse to send");
    assert_eq!(err.code(), Some(-13), "expected unlock-needed (-13): {err}");
    let err = zecd
        .call("walletpassphrase", json!(["wrong-pass", 600]))
        .await
        .expect_err("a wrong passphrase must be rejected");
    assert_eq!(
        err.code(),
        Some(-14),
        "expected passphrase-incorrect (-14): {err}"
    );
    zecd.call("walletpassphrase", json!([ENCRYPT_PASSPHRASE, 3600]))
        .await
        .expect("the real passphrase unlocks");
    let wi = zecd
        .call("getwalletinfo", json!([]))
        .await
        .expect("getwalletinfo");
    assert!(
        wi["unlocked_until"].as_i64().unwrap_or(0) > 0,
        "unlocked_until reports the relock time while unlocked: {wi}"
    );

    // The send-success path: a real Orchard spend back to the funder, carrying a ZIP-302
    // memo via the trailing extension param (after Bitcoin Core's comment/fee-knob/verbose
    // slots): hex for "regtest memo".
    let memo_hex = "72656774657374206d656d6f";
    // `getbalance` can report the funded note spendable (relative to the chain tip) before the
    // wallet has scanned to that depth, so explicitly wait for the scan to reach the tip before
    // this first spend - otherwise note selection finds it not-yet-spendable and the send fails
    // -6. The later sends already wait_until_synced after their mining; this first one didn't.
    let chain_tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount")
        .as_u64()
        .expect("tip height");
    zecd.wait_until_synced(chain_tip, FUND_TIMEOUT)
        .await
        .expect("zecd scans to the tip before the first send");
    let txid = zecd
        .call(
            "sendtoaddress",
            json!([funder_ua, 0.4, "", "", null, null, null, null, null, null, null, memo_hex]),
        )
        .await
        .expect("sendtoaddress succeeds with spendable funds");
    let txid = txid.as_str().expect("txid is a string").to_string();
    assert_eq!(txid.len(), 64, "txid is display hex");

    // gettransaction immediately: unconfirmed send shape (amount excludes the fee).
    let gt = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction on our own send");
    assert_eq!(
        gt["amount"].as_f64(),
        Some(-0.4),
        "gettransaction.amount is the negated payment, fee excluded: {gt}"
    );
    assert!(
        gt["fee"].as_f64().is_some_and(|f| f < 0.0),
        "fee is present and negative: {gt}"
    );
    assert_eq!(gt["confirmations"].as_i64(), Some(0), "not yet mined: {gt}");
    assert!(
        gt["hex"].as_str().is_some_and(|h| !h.is_empty()),
        "raw hex is stored for our own send: {gt}"
    );
    // The send detail's address is the single on-chain Orchard receiver actually paid, not the
    // full multi-receiver UA the caller typed: zecd reduces every outgoing recipient to its paid
    // receiver so history is identical on the authoring instance and after a restore-from-seed
    // (where only the paid receiver is recoverable from chain). So match the (sole) send detail
    // by category and assert the reduced address is a non-empty Unified Address, rather than
    // equality with the multi-receiver `funder_ua`.
    let send_detail = gt["details"]
        .as_array()
        .expect("details")
        .iter()
        .find(|d| d["category"] == "send")
        .cloned()
        .unwrap_or_else(|| panic!("details carry the send to the funder: {gt}"));
    assert!(
        send_detail["address"]
            .as_str()
            .is_some_and(|a| a.starts_with('u') && a != funder_ua),
        "send detail carries the reduced single-receiver Orchard UA: {send_detail}"
    );
    // The memo round-trips onto the send detail (hex + decoded text, zcashd's field names).
    assert_eq!(
        send_detail["memo"].as_str(),
        Some(memo_hex),
        "send detail carries the memo hex: {send_detail}"
    );
    assert_eq!(
        send_detail["memoStr"].as_str(),
        Some("regtest memo"),
        "send detail decodes the text memo: {send_detail}"
    );
    // WalletTxToJSON fields on an unconfirmed own send: trusted (we authored it and it can
    // still mine), walletconflicts always present, and a real time (the wallet's `created`
    // timestamp - Bitcoin Core semantics, where unmined txs carry their first-seen time).
    assert_eq!(
        gt["trusted"].as_bool(),
        Some(true),
        "own unmined send is trusted: {gt}"
    );
    assert!(
        gt["walletconflicts"].is_array(),
        "walletconflicts is always present: {gt}"
    );
    assert!(
        gt["time"].as_i64().is_some_and(|t| t > 0),
        "an unmined send reports a real time, not 0: {gt}"
    );

    // Mine it in and let zecd scan; the send confirms.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(3).await.expect("confirm the send");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("zecd scans the confirming blocks");
    let gt = zecd
        .call("gettransaction", json!([txid]))
        .await
        .expect("gettransaction after mining");
    assert!(
        gt["confirmations"].as_i64().is_some_and(|c| c >= 1),
        "the send is confirmed: {gt}"
    );
    assert!(gt["blockheight"].is_u64(), "mined height is reported: {gt}");
    assert!(
        gt["blockhash"].as_str().is_some_and(|h| h.len() == 64),
        "mined send carries its blockhash: {gt}"
    );
    assert!(
        gt["blocktime"].as_i64().is_some_and(|t| t > 0),
        "mined send carries its blocktime: {gt}"
    );
    assert!(
        gt.get("trusted").is_none(),
        "trusted rides on unmined txs only once confirmed: {gt}"
    );

    // The poller loop closes: since the pre-send cursor, the send appears; since the fresh
    // cursor, nothing confirmed is left to report.
    let lsb = zecd
        .call("listsinceblock", json!([cursor]))
        .await
        .expect("listsinceblock since the pre-send cursor");
    assert!(
        lsb["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .any(|t| { t["txid"] == json!(txid.as_str()) && t["category"] == "send" }),
        "the send is reported since the pre-send cursor: {lsb}"
    );
    let cursor2 = lsb["lastblock"]
        .as_str()
        .expect("new lastblock")
        .to_string();
    let lsb2 = zecd
        .call("listsinceblock", json!([cursor2]))
        .await
        .expect("listsinceblock since the fresh cursor");
    assert!(
        lsb2["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .all(|t| t["confirmations"].as_i64().unwrap_or(0) < 1),
        "nothing confirmed is re-reported past the fresh cursor: {lsb2}"
    );

    // ---- Phase 3: send during an upstream outage (the committed-send contract) ----

    // Give the Phase-2 change a comfortable confirmation margin first: trusted change needs
    // 3 confirmations and the Phase-2 send may have landed in *any* of the 3 just-mined
    // blocks (mempool/template timing), so without this buffer Phase 3's spendable balance
    // is a race.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad
        .generate_blocks(4)
        .await
        .expect("mature the Phase-2 change");
    zecd.wait_until_synced(tip + 4, FUND_TIMEOUT)
        .await
        .expect("scan the change-maturity blocks");

    // Hang the upstream (SIGSTOP zebra), then send: the wallet must commit and return the txid
    // even though the broadcast can't reach anyone - recovery is the rebroadcast loop's job.
    zebrad.pause().expect("SIGSTOP zebra (outage)");
    let txid_outage = zecd
        .call("sendtoaddress", json!([funder_ua, 0.1]))
        .await
        .expect("a committed send returns its txid even when broadcast fails");
    let txid_outage = txid_outage.as_str().expect("txid is a string").to_string();
    let gt = zecd
        .call("gettransaction", json!([txid_outage]))
        .await
        .expect("gettransaction during the outage");
    assert_eq!(
        gt["confirmations"].as_i64(),
        Some(0),
        "committed, unmined: {gt}"
    );

    // The daemon reports the outage once the actor notices the dead connection.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let peers = zecd
            .call("getpeerinfo", json!([]))
            .await
            .expect("getpeerinfo");
        if peers.as_array().is_some_and(|a| a.is_empty()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "getpeerinfo never emptied during the outage: {peers}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // The health endpoints report the same outage: /healthz stays 200 (pure liveness),
    // /readyz flips to 503 with reason "upstream_down", and /status shows the wallet's
    // conn_state as "down".
    let health = format!("http://127.0.0.1:{}", cfg.health_port());
    let resp = reqwest::get(format!("{health}/healthz"))
        .await
        .expect("GET /healthz");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "/healthz is liveness, not readiness"
    );
    let resp = reqwest::get(format!("{health}/readyz"))
        .await
        .expect("GET /readyz");
    assert_eq!(
        resp.status().as_u16(),
        503,
        "/readyz is 503 during the outage"
    );
    let body: serde_json::Value = resp.json().await.expect("readyz body is JSON");
    assert_eq!(body["ready"], json!(false), "{body}");
    assert_eq!(body["reason"], json!("upstream_down"), "{body}");
    let st: serde_json::Value = reqwest::get(format!("{health}/status"))
        .await
        .expect("GET /status")
        .json()
        .await
        .expect("status body is JSON");
    assert_eq!(st["network"], json!("regtest"), "{st}");
    assert_eq!(
        st["wallets"]["default"]["conn_state"],
        json!("down"),
        "{st}"
    );

    // Upstream recovers: zecd reconnects (1-2s backoff), the rebroadcast pass (2s interval)
    // re-submits the tx, and mining confirms it.
    zebrad.resume().expect("SIGCONT zebra (recovery)");
    mine_until_confirmed(&zebrad, &zecd, &txid_outage, "outage send after recovery").await;

    // /readyz returns to 200 once the wallet is reconnected and caught up again.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let resp = reqwest::get(format!("{health}/readyz"))
            .await
            .expect("GET /readyz");
        if resp.status().as_u16() == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "/readyz did not return to 200 after the upstream recovered"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ---- Phase 4: a second confirmed send ----
    //
    // The lightwalletd harness used this slot to test tx *expiry* (a committed send that can
    // never broadcast eventually expires and releases its funds). That flow needs the broadcast
    // path down while the chain keeps advancing - two roles a single local zebra node can't
    // separate (zecd would reconnect and rebroadcast the tx, which then mines) - so expiry and
    // abandonment are covered by unit tests, not this e2e. A plain confirmed send keeps the
    // wallet balance where the concurrent-send burst below expects it (~0.4 ZEC).
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(3).await.expect("mature the change");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("zecd scans the maturity blocks");
    let txid_p4 = zecd
        .call("sendtoaddress", json!([funder_ua, 0.1]))
        .await
        .expect("a normal send succeeds")
        .as_str()
        .expect("txid is a string")
        .to_string();
    mine_until_confirmed(&zebrad, &zecd, &txid_p4, "phase-4 send").await;

    // ---- concurrent-send burst: the no-double-spend invariant under contention ----
    //
    // After Phases 2-4 the wallet holds ~0.4 ZEC (1.0 received − 0.4 − 0.1 − 0.1 − fees).
    // Fire four concurrent sendtoaddress of 0.25: two successes would need 0.5, more than the
    // wallet holds, so *exactly one* can succeed no matter how change was split into notes -
    // the rest must serialize behind it in the wallet actor and fail with -6 (insufficient
    // funds), never by double-spending the same note. This is the CI version of the manual
    // "busy-server demo".
    //
    // First let the Phase-4 retry's change age past the trusted-note depth (3, plus one for
    // the block the retry itself may have landed in) so the burst has spendable notes.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(4).await.expect("age the change");
    zecd.wait_until_synced(tip + 4, FUND_TIMEOUT)
        .await
        .expect("zecd scans the change-aging blocks");

    let burst = json!([funder_ua, 0.25]);
    // While the burst is in flight, getrpcinfo.active_commands must show the concurrent
    // sendtoaddress calls - the manual "busy-server demo" assertion, in CI. The losers
    // queue behind the winner's proving in the wallet actor, so the window is wide.
    let watch_active = async {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let ri = zecd
                .call("getrpcinfo", json!([]))
                .await
                .expect("getrpcinfo");
            let in_flight = ri["active_commands"]
                .as_array()
                .expect("active_commands")
                .iter()
                .filter(|c| c["method"] == "sendtoaddress")
                .count();
            if in_flight >= 1 {
                break in_flight;
            }
            if Instant::now() >= deadline {
                break 0;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    };
    let (a, b, c, d, seen_in_flight) = tokio::join!(
        zecd.call("sendtoaddress", burst.clone()),
        zecd.call("sendtoaddress", burst.clone()),
        zecd.call("sendtoaddress", burst.clone()),
        zecd.call("sendtoaddress", burst.clone()),
        watch_active,
    );
    assert!(
        seen_in_flight >= 1,
        "getrpcinfo.active_commands showed the burst in flight"
    );
    let results = [a, b, c, d];
    let winners: Vec<&str> = results
        .iter()
        .filter_map(|r| r.as_ref().ok().and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent send can be funded: {results:?}"
    );
    let winner_txid = winners[0].to_string();
    assert_eq!(winner_txid.len(), 64, "winning txid is display hex");
    for r in &results {
        if let Err(e) = r {
            assert_eq!(
                e.code(),
                Some(-6),
                "every losing concurrent send fails with insufficient-funds (-6): {e}"
            );
        }
    }

    // The winner is a real transaction: it mines and confirms like any other send.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad.generate_blocks(3).await.expect("confirm the winner");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("zecd scans the winner's confirmations");
    let gt = zecd
        .call("gettransaction", json!([winner_txid]))
        .await
        .expect("gettransaction on the burst winner");
    assert!(
        gt["confirmations"].as_i64().is_some_and(|c| c >= 1),
        "the burst winner confirmed on-chain: {gt}"
    );

    // ---- Phase 6: sendmany - the multi-output happy path ----
    //
    // A 2-output sendmany pays the funder's unified address AND its transparent address in
    // one transaction: the multi-output proposal path and a transparent (deshielding)
    // recipient, neither of which any other automated test exercises. First age the burst
    // change to trusted spendability (3 confs, +1 for the block the winner landed in).
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad
        .generate_blocks(4)
        .await
        .expect("age the burst change");
    zecd.wait_until_synced(tip + 4, FUND_TIMEOUT)
        .await
        .expect("scan the change-aging blocks");

    let mut recipients = serde_json::Map::new();
    recipients.insert(funder_ua.clone(), json!(0.05));
    recipients.insert(funder_taddr.clone(), json!(0.02));
    let txid_many = zecd
        .call("sendmany", json!(["", recipients]))
        .await
        .expect("sendmany with two recipients succeeds");
    let txid_many = txid_many.as_str().expect("txid is a string").to_string();
    assert_eq!(txid_many.len(), 64, "sendmany txid is display hex");

    let gt = zecd
        .call("gettransaction", json!([txid_many]))
        .await
        .expect("gettransaction on the sendmany");
    assert_eq!(
        gt["amount"].as_f64(),
        Some(-0.07),
        "amount sums both outputs, fee excluded: {gt}"
    );
    assert!(
        gt["fee"].as_f64().is_some_and(|f| f < 0.0),
        "fee is present and negative: {gt}"
    );
    let sends: Vec<_> = gt["details"]
        .as_array()
        .expect("details")
        .iter()
        .filter(|d| d["category"] == "send")
        .cloned()
        .collect();
    assert_eq!(sends.len(), 2, "one send detail per recipient: {gt}");
    // The shielded recipient (the multi-receiver `funder_ua`) is reduced to the single Orchard
    // receiver actually paid, so match it by amount and assert the reduced address is a non-empty
    // UA. The transparent recipient is a bare t-addr - already a single receiver, so it reduces
    // to itself and the exact-equality check still holds.
    assert!(
        sends.iter().any(|d| d["amount"].as_f64() == Some(-0.05)
            && d["address"].as_str().is_some_and(|a| a.starts_with('u'))),
        "the shielded recipient detail carries its reduced receiver and amount: {gt}"
    );
    assert!(
        sends
            .iter()
            .any(|d| d["address"] == json!(funder_taddr.as_str())
                && d["amount"].as_f64() == Some(-0.02)),
        "the transparent recipient detail carries its address and amount: {gt}"
    );
    mine_until_confirmed(&zebrad, &zecd, &txid_many, "2-output sendmany").await;

    // ---- Phase 6b: z_sendmany - the asynchronous send + operation tracking ----
    //
    // zcashd's async send: z_sendmany returns an opid immediately and proves/broadcasts the
    // transaction on a background task, tracked by z_getoperationstatus / z_getoperationresult
    // / z_listoperationids. First age the 2-output-sendmany change to spendability so the async
    // send has notes to spend.
    let tip = zecd.block_count().await.expect("getblockcount");
    zebrad
        .generate_blocks(4)
        .await
        .expect("age the sendmany change");
    zecd.wait_until_synced(tip + 4, FUND_TIMEOUT)
        .await
        .expect("scan the change-aging blocks");

    // fromaddress is zecd's own account address (zcashd requires one; zecd validates ownership).
    let opid = zecd
        .call(
            "z_sendmany",
            json!([zecd_ua, [{ "address": funder_ua, "amount": 0.01 }]]),
        )
        .await
        .expect("z_sendmany returns an operation id");
    let opid = opid.as_str().expect("opid is a string").to_string();
    assert!(opid.starts_with("opid-"), "opid shape: {opid}");

    // The operation is immediately visible in z_listoperationids for this wallet.
    let ids = zecd
        .call("z_listoperationids", json!([]))
        .await
        .expect("z_listoperationids");
    assert!(
        ids.as_array()
            .expect("array")
            .iter()
            .any(|v| v == &json!(opid)),
        "new opid appears in z_listoperationids: {ids}"
    );

    // Poll z_getoperationstatus until the background send finishes (60s budget covers a debug
    // build's slow proving); a failed operation fails the test.
    let mut op_txid = None;
    for _ in 0..120 {
        let st = zecd
            .call("z_getoperationstatus", json!([[opid]]))
            .await
            .expect("z_getoperationstatus");
        let obj = st
            .as_array()
            .expect("status array")
            .first()
            .expect("our operation is present")
            .clone();
        assert_eq!(obj["id"], json!(opid), "status carries our opid: {obj}");
        match obj["status"].as_str().expect("status string") {
            "success" => {
                assert!(
                    !obj["execution_secs"].is_null(),
                    "a successful op reports execution_secs: {obj}"
                );
                op_txid = Some(
                    obj["result"]["txid"]
                        .as_str()
                        .expect("a successful op carries result.txid")
                        .to_string(),
                );
                break;
            }
            "failed" => panic!("z_sendmany operation failed: {obj}"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    let op_txid = op_txid.expect("z_sendmany operation reached success");
    assert_eq!(op_txid.len(), 64, "operation result txid is display hex");

    // z_getoperationresult returns the finished op exactly once and removes it from memory.
    let res = zecd
        .call("z_getoperationresult", json!([[opid]]))
        .await
        .expect("z_getoperationresult");
    let res = res.as_array().expect("result array");
    assert_eq!(res.len(), 1, "one finished op is returned: {res:?}");
    assert_eq!(res[0]["result"]["txid"], json!(op_txid));
    let after = zecd
        .call("z_getoperationstatus", json!([[opid]]))
        .await
        .expect("z_getoperationstatus after result");
    assert!(
        after.as_array().expect("array").is_empty(),
        "operation removed after z_getoperationresult: {after}"
    );

    mine_until_confirmed(&zebrad, &zecd, &op_txid, "z_sendmany async operation").await;

    // ---- Phase 6c: z_sendmany failure + tracking edge cases ----
    //
    // These exercise branches that need real chain state / foreign addresses: fromaddress
    // ownership, the FullPrivacy per-call policy, a *failed* async operation (and that minconf
    // is honored), and multiwallet scoping of the tracking RPCs.

    // A syntactically valid but foreign fromaddress is rejected by the ownership check (-5),
    // distinct from the undecodable-address case the conformance suite covers.
    let err = zecd
        .call(
            "z_sendmany",
            json!([funder_ua, [{ "address": funder_ua, "amount": 0.001 }]]),
        )
        .await
        .expect_err("a fromaddress that isn't the wallet's own must be rejected");
    assert_eq!(err.code(), Some(-5), "foreign fromaddress -> -5: {err}");

    // FullPrivacy (per-call) must reject a transparent recipient, mapping through to build_payment.
    let err = zecd
        .call(
            "z_sendmany",
            json!([zecd_ua, [{ "address": funder_taddr, "amount": 0.001 }], null, null, "FullPrivacy"]),
        )
        .await
        .expect_err("FullPrivacy must reject a transparent recipient");
    assert_eq!(
        err.code(),
        Some(-8),
        "FullPrivacy + transparent recipient -> -8: {err}"
    );

    // AllowRevealedAmounts is the intermediate rung: it opts into revealing *amounts* (a
    // Sapling<->Orchard crossing) but NOT *recipients*, so a transparent recipient must still be
    // -8 - exactly as zcashd rejects it. Regression guard for the collapse bug where the three
    // mid-tier policies all fell through to fully-permissive and silently paid transparent.
    let err = zecd
        .call(
            "z_sendmany",
            json!([zecd_ua, [{ "address": funder_taddr, "amount": 0.001 }], null, null, "AllowRevealedAmounts"]),
        )
        .await
        .expect_err("AllowRevealedAmounts must reject a transparent recipient");
    assert_eq!(
        err.code(),
        Some(-8),
        "AllowRevealedAmounts + transparent recipient -> -8: {err}"
    );

    // A memo-only send: zcashd's standard pattern is a zero-valued output to a shielded recipient
    // carrying a memo. z_sendmany must accept `amount: 0` (the Bitcoin-Core-dialect sends still
    // reject it) and build a valid transaction - proved end-to-end here, not just that
    // build_payment stops rejecting it.
    let memo_only_memo = "6d656d6f2d6f6e6c79"; // "memo-only"
    let opid = zecd
        .call(
            "z_sendmany",
            json!([zecd_ua, [{ "address": funder_ua, "amount": 0, "memo": memo_only_memo }]]),
        )
        .await
        .expect("z_sendmany accepts a zero-valued memo-only output")
        .as_str()
        .expect("opid string")
        .to_string();
    let mut memo_only_txid = None;
    for _ in 0..120 {
        let st = zecd
            .call("z_getoperationstatus", json!([[opid]]))
            .await
            .expect("z_getoperationstatus");
        let obj = st
            .as_array()
            .expect("status array")
            .first()
            .expect("our operation is present")
            .clone();
        match obj["status"].as_str().expect("status string") {
            "success" => {
                memo_only_txid = Some(
                    obj["result"]["txid"]
                        .as_str()
                        .expect("a successful op carries result.txid")
                        .to_string(),
                );
                break;
            }
            "failed" => panic!("the memo-only (amount 0) send must succeed: {obj}"),
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    let memo_only_txid = memo_only_txid.expect("the memo-only send reached success");
    mine_until_confirmed(&zebrad, &zecd, &memo_only_txid, "z_sendmany memo-only send").await;

    // minconf is honored: an absurd minconf makes the send unsatisfiable, so the async op
    // reaches `failed` (whereas the default-minconf send in Phase 6b succeeded - that A/B is
    // the proof minconf threads through). The concrete error is librustzcash's
    // `-4 "Must scan blocks first"` (the requested anchor depth is unreachable), so assert the
    // failed-op *shape* - a negative code + a message, no result - not one exact error code.
    let opid = zecd
        .call(
            "z_sendmany",
            json!([zecd_ua, [{ "address": funder_ua, "amount": 0.001 }], 9_999_999]),
        )
        .await
        .expect("z_sendmany with a high minconf still returns an opid")
        .as_str()
        .expect("opid string")
        .to_string();
    let mut saw_failed = false;
    for _ in 0..120 {
        let st = zecd
            .call("z_getoperationstatus", json!([[opid]]))
            .await
            .expect("z_getoperationstatus");
        let obj = st
            .as_array()
            .expect("status array")
            .first()
            .expect("our operation is present")
            .clone();
        match obj["status"].as_str().expect("status string") {
            "failed" => {
                let err = &obj["error"];
                assert!(
                    err["code"].as_i64().is_some_and(|c| c < 0),
                    "the failed op carries a negative JSON-RPC error code: {obj}"
                );
                assert!(
                    err["message"].as_str().is_some_and(|m| !m.is_empty()),
                    "the failed op carries an error message: {obj}"
                );
                assert!(
                    obj.get("result").is_none(),
                    "no result on a failed op: {obj}"
                );
                saw_failed = true;
                break;
            }
            "success" => panic!("z_sendmany with minconf=9999999 must not succeed: {obj}"),
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    assert!(
        saw_failed,
        "the high-minconf operation reached the failed state"
    );

    // The tracking RPCs are wallet-routed: an unknown wallet is -18.
    let err = zecd
        .call_wallet("nope", "z_listoperationids", json!([]))
        .await
        .expect_err("an unknown wallet must be rejected");
    assert_eq!(err.code(), Some(-18), "unknown wallet -> -18: {err}");

    // ---- Phase 7: sendrawtransaction ----
    //
    // Send normally (the tx lands in the node's mempool), capture its raw hex, then re-submit
    // it with sendrawtransaction: the node already has it, so - like Bitcoin Core - the call is
    // idempotent and returns the canonical txid rather than erroring. (The lightwalletd harness
    // staged a committed-but-*unbroadcast* tx here by sending during an outage and delivering it
    // by hand; that needs the broadcast path down while the chain advances, which a single zebra
    // node can't do, so this covers sendrawtransaction's accept/idempotency contract instead.)
    let txid_raw = zecd
        .call("sendtoaddress", json!([funder_ua, 0.01]))
        .await
        .expect("send")
        .as_str()
        .expect("txid is a string")
        .to_string();
    let raw_hex = zecd
        .call("gettransaction", json!([txid_raw]))
        .await
        .expect("gettransaction")["hex"]
        .as_str()
        .expect("raw hex is stored for the committed send")
        .to_string();
    let echoed = zecd
        .call("sendrawtransaction", json!([raw_hex]))
        .await
        .expect("sendrawtransaction accepts the committed raw bytes");
    assert_eq!(
        echoed.as_str(),
        Some(txid_raw.as_str()),
        "sendrawtransaction returns the canonical txid for a tx already in the mempool"
    );
    mine_until_confirmed(&zebrad, &zecd, &txid_raw, "sendrawtransaction send").await;

    // ---- Phase 8: a self-send (pay our own address) is visible and carries its memo ----
    //
    // librustzcash marks *any* output received by an account that also spent in the same
    // transaction as `is_change` (scanning's `find_received`: `is_change =
    // spent_from_accounts.contains(..)`), so a deliberate payment to one of the wallet's own
    // user-facing addresses lands with `is_change = true` even though it was received on an
    // external-scope address. zecd must still surface it - Bitcoin Core shows a self-send as a
    // send+receive pair - so the memo on a self-directed output stays reachable. (The
    // discriminator is the recipient key scope, not `is_change`: external = a real payment,
    // internal = true change.) Before the fix this whole transaction vanished from
    // gettransaction/listtransactions/z_listtransactions and the memo was unreachable.

    // Mature the Phase-7 change so the self-send has a spendable note (trusted depth 3 + skew).
    let tip = zecd
        .block_count()
        .await
        .expect("getblockcount before the self-send");
    zebrad
        .generate_blocks(4)
        .await
        .expect("mature change before the self-send");
    zecd.wait_until_synced(tip + 4, FUND_TIMEOUT)
        .await
        .expect("scan the maturing blocks");

    // A fresh own address (external/user-facing) and a ZIP-302 text memo to ourselves.
    let self_addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress for the self-send")
        .as_str()
        .expect("address is a string")
        .to_string();
    let self_memo_hex = "676d3a2073656c662d73656e64"; // "gm: self-send"
    let self_memo_text = "gm: self-send";
    let self_txid = zecd
        .call(
            "sendtoaddress",
            json!([
                self_addr,
                0.001,
                "",
                "",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                self_memo_hex
            ]),
        )
        .await
        .expect("self-send succeeds")
        .as_str()
        .expect("txid is a string")
        .to_string();

    let tip = zecd
        .block_count()
        .await
        .expect("getblockcount before confirm");
    zebrad
        .generate_blocks(3)
        .await
        .expect("confirm the self-send");
    zecd.wait_until_synced(tip + 3, FUND_TIMEOUT)
        .await
        .expect("scan the confirming blocks");

    // The receive side's memo is backfilled by transaction enhancement (compact blocks carry
    // no memos), which runs a beat after the scan reaches the tip - poll for it. When it lands,
    // assert the full self-send shape: a send+receive pair on our own address, memo on receive.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let gt = zecd
            .call("gettransaction", json!([self_txid]))
            .await
            .expect("gettransaction on the self-send");
        let details = gt["details"].as_array().cloned().unwrap_or_default();
        let recv = details
            .iter()
            .find(|d| d["category"] == "receive" && d["memoStr"].as_str() == Some(self_memo_text));
        if let Some(recv) = recv {
            // The receive is to our own address and carries both memo encodings.
            assert_eq!(
                recv["address"].as_str(),
                Some(self_addr.as_str()),
                "self-send receive is to our own address: {recv}"
            );
            assert_eq!(
                recv["memo"].as_str(),
                Some(self_memo_hex),
                "self-send receive carries the raw memo hex: {recv}"
            );
            // The matching send side: negative, to the same address, with the fee.
            let send = details
                .iter()
                .find(|d| d["category"] == "send" && d["address"] == json!(self_addr.as_str()))
                .unwrap_or_else(|| panic!("self-send has a send detail: {gt}"));
            assert!(
                send["amount"].as_f64().is_some_and(|a| a < 0.0),
                "self-send debit is negative: {send}"
            );
            assert!(
                send["fee"].as_f64().is_some_and(|f| f < 0.0),
                "self-send send detail carries the fee: {send}"
            );

            // listtransactions surfaces both halves (it used to drop the tx entirely).
            let lt = zecd
                .call("listtransactions", json!(["*", 50]))
                .await
                .expect("listtransactions");
            let mine: Vec<_> = lt
                .as_array()
                .expect("array")
                .iter()
                .filter(|t| t["txid"] == json!(self_txid.as_str()))
                .collect();
            assert!(
                mine.iter().any(|t| t["category"] == "send"),
                "listtransactions shows the self-send's send entry: {lt}"
            );
            assert!(
                mine.iter()
                    .any(|t| t["category"] == "receive"
                        && t["memoStr"].as_str() == Some(self_memo_text)),
                "listtransactions shows the self-send's receive entry + memo: {lt}"
            );

            // z_listtransactions (zcashd vocabulary) surfaces the receive + memo too.
            let zlt = zecd
                .call("z_listtransactions", json!([50]))
                .await
                .expect("z_listtransactions");
            assert!(
                zlt.as_array()
                    .expect("array")
                    .iter()
                    .any(|t| t["txid"] == json!(self_txid.as_str())
                        && t["category"] == "receive"
                        && t["memoStr"].as_str() == Some(self_memo_text)),
                "z_listtransactions surfaces the self-send receive + memo: {zlt}"
            );

            // getreceivedbyaddress counts the self-payment to that address (Bitcoin Core does).
            let received = zecd
                .call("getreceivedbyaddress", json!([self_addr, 1]))
                .await
                .expect("getreceivedbyaddress on the self-send address");
            assert_eq!(
                received.as_f64(),
                Some(0.001),
                "getreceivedbyaddress counts the self-payment: {received}"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the self-send never surfaced its receive memo: {gt}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ---- conformance.py against the live, funded daemon ----
    // The wallet was created encrypted (`init --encrypt`) and is unlocked by now; passing the
    // passphrase enables conformance's lock/unlock state machine (unlock → walletlock → -13 →
    // re-unlock). At-rest encryption is set once at init; there is no passphrase-mutating RPC.
    run_conformance(
        cfg.rpc_port,
        &cfg.rpc_user,
        &cfg.rpc_password,
        ENCRYPT_PASSPHRASE,
    );

    // ---- enhancement guard: a received memo is recovered from a scratch scan ----
    //
    // The live receive above got its memo from the mempool stream (the full tx was
    // trial-decrypted and stored before it mined), so it alone can't prove the transaction-
    // *enhancement* path. A from-scratch scan can: a fresh wallet rebuilds purely from compact
    // blocks (which carry no memos), so the only way a received memo can reappear is the
    // enhancement step fetching the full transaction and decrypting it. We use a watch-only
    // wallet built from the funded wallet's UFVK - same account, so it scans the same received
    // note, and the viewing key is enough to decrypt the incoming memo. (Watch-only over a
    // mnemonic restore because the UFVK is passed as a CLI arg, sidestepping stdin.)
    let ufvk = zecd
        .export_ufvk("default")
        .expect("export the funded wallet's UFVK");
    let mut watch_cfg = ZecdConfig::new(
        zebrad.rpc_port,
        pick_port().expect("pick watch-only rpc port"),
    );
    watch_cfg.ufvk = Some(ufvk);
    watch_cfg.birthday = Some(2);
    let watch_only = Zecd::start(&watch_cfg)
        .await
        .expect("start the watch-only wallet");
    let tip = zecd
        .block_count()
        .await
        .expect("getblockcount before the watch-only sync");
    watch_only
        .wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the watch-only wallet scans from birthday to the tip");

    // The received memo is recovered, but only after enhancement runs - which happens on a
    // caught-up pass, a beat after the block scan reaches the tip. Poll for it.
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let txs = watch_only
            .call("listtransactions", json!(["*", 100]))
            .await
            .expect("listtransactions on the watch-only wallet");
        let recovered = txs
            .as_array()
            .expect("array")
            .iter()
            .any(|t| t["category"] == "receive" && t["memoStr"].as_str() == Some(RECEIVE_MEMO));
        if recovered {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the watch-only wallet never recovered the received memo via enhancement: {txs}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // The enhancement backlog is an observable signal, not just an internal step: once the drain
    // completes, /status must report `pending_enhancements: 0` and the connection back to `ready`
    // (it stays `syncing` while the backlog drains, even after the block scan reaches the tip).
    // This is the end-to-end check that the headline bug - "sync complete" hiding the backlog - is
    // fixed: the field is plumbed actor → SyncStatus → /status and reaches zero.
    let watch_health = format!("http://127.0.0.1:{}", watch_cfg.health_port());
    let deadline = Instant::now() + FUND_TIMEOUT;
    loop {
        let st: serde_json::Value = reqwest::get(format!("{watch_health}/status"))
            .await
            .expect("GET /status on the watch-only wallet")
            .json()
            .await
            .expect("watch-only /status body is JSON");
        let w = &st["wallets"]["default"];
        if w["pending_enhancements"] == json!(0) && w["conn_state"] == json!("ready") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the watch-only wallet's enhancement backlog never drained: {st}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ---- bootstrap: rebuild data.sqlite from keys.toml on an empty data directory ----
    //
    // The cloud-native Phase-1 guarantee end to end on a real chain: wipe the wallet's
    // data.sqlite + block cache (leaving keys.toml), restart, and confirm the daemon rebuilds
    // the account from keys.toml and the funds - and spendability - come back. The wallet is
    // encrypted, so this also exercises the locked path: it comes back with no account, refuses
    // address generation, and only rebuilds once `walletpassphrase` supplies the seed.
    drop(watch_only);
    let tip = zecd
        .block_count()
        .await
        .expect("getblockcount before the data-dir wipe (wallet is synced)");
    let balance_before = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance before the data-dir wipe");

    zecd.restart_wiping_data_db()
        .await
        .expect("restart zecd on an emptied data directory");

    // Locked, encrypted, empty datadir: no account yet, so address generation is refused until
    // the passphrase arrives.
    let pre_unlock = zecd.call("getnewaddress", json!([])).await;
    assert!(
        pre_unlock.is_err(),
        "a locked, not-yet-bootstrapped wallet must refuse getnewaddress, got {pre_unlock:?}"
    );

    // The first walletpassphrase supplies the seed; the actor rebuilds the account from
    // keys.toml and rescans from the birthday.
    zecd.call("walletpassphrase", json!([ENCRYPT_PASSPHRASE, 3600]))
        .await
        .expect("walletpassphrase unlocks and triggers the rebuild");
    zecd.wait_until_synced(tip, FUND_TIMEOUT)
        .await
        .expect("the rebuilt wallet rescans back to the tip");

    let balance_after = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance after the rebuild");
    assert_eq!(
        balance_after, balance_before,
        "the rebuilt wallet recovers the same balance"
    );

    // The rebuilt account can actually sign and broadcast: a real send back to the funder.
    let funder_ua = funder.unified_address().expect("funder unified address");
    let send = zecd
        .call("sendtoaddress", json!([funder_ua, 0.01]))
        .await
        .expect("the rebuilt wallet signs and broadcasts a spend");
    let send_txid = send.as_str().expect("sendtoaddress txid").to_string();
    mine_until_confirmed(&zebrad, &zecd, &send_txid, "post-rebuild send").await;
}

/// Mine one block at a time (giving the rebroadcast/scan loop time between blocks) until
/// zecd reports the tx confirmed. Panics after ~30 rounds.
async fn mine_until_confirmed(zebrad: &Zebrad, zecd: &Zecd, txid: &str, what: &str) {
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        zebrad.generate_blocks(1).await.expect("mine a block");
        let gt = zecd
            .call("gettransaction", json!([txid]))
            .await
            .expect("gettransaction while polling for confirmation");
        if gt["confirmations"].as_i64().unwrap_or(0) >= 1 {
            return;
        }
    }
    panic!("{what}: tx {txid} did not confirm within the mining budget");
}

/// Run `scripts/conformance.py` (the python-bitcoinrpc-equivalent wire-format suite) against
/// the regtest daemon. Skips with a notice if `python3` isn't available so local runs without
/// it don't fail confusingly; CI always has it.
fn run_conformance(rpc_port: u16, user: &str, password: &str, passphrase: &str) {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness lives inside the zecd repo")
        .join("scripts/conformance.py");
    let out = std::process::Command::new("python3")
        .arg(&script)
        .args([
            "--url",
            &format!("http://127.0.0.1:{rpc_port}/"),
            "--user",
            user,
            "--password",
            password,
            "--passphrase",
            passphrase,
        ])
        .output();
    match out {
        Err(e) => eprintln!("SKIP conformance.py: python3 unavailable ({e})"),
        Ok(out) => {
            println!("{}", String::from_utf8_lossy(&out.stdout));
            assert!(
                out.status.success(),
                "conformance.py reported failures:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
