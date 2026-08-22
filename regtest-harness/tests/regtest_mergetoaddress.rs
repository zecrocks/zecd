//! `z_mergetoaddress` consolidation e2e over a deliberately fragmented wallet: more transparent
//! UTXOs (56) than zcashd's default `transparent_limit` (50), plus enough shielded notes (12)
//! to exercise both shielded-merge paths - the manual limited selection (via an explicit
//! `shielded_limit` that binds) and the unlimited `propose_send_max` delegation - through
//! multi-round convergence down to a single note and a final amountless z→t sweep.
//!
//! The transparent set is sized to zcashd's default `transparent_limit` because that default is
//! itself the assertion, and transparent inputs cost no Orchard actions. The note set is sized
//! to the binding limit instead - see [`N_FANOUT_OUTPUTS`].
//!
//! **The fixture is funder-built on purpose.** Fanning a wallet out with its own self-sends
//! cannot work: librustzcash selects notes oldest-first (by commitment tree position), so later
//! fan-out rounds spend the earlier rounds' small payment notes - the first CI run of a
//! self-send version measured it directly (round 4 drew 38 inputs and the wallet topped out at
//! 176 notes instead of 208+). The funder paying N distinct addresses per `z_sendmany` leaves
//! the wallet under test's notes untouched, and its fan-out proofs run on the funder, keeping
//! this binary's wall clock near the tier's envelope.
//!
//! The **>200-notes default-`shielded_limit`** case (a defaults call reporting exactly
//! `mergingNotes: 200` against a 225-note wallet, then draining the rest) costs ~200 actions of
//! proving per round on both the fan-out and merge sides, so it lives in the second, extended
//! -tier test below (`ZECD_REGTEST_EXTENDED=1`, weekly + dispatch), like the other heavy e2es.
//!
//! Skips cleanly unless `ZEBRAD_BIN` is set.

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zecd_regtest_harness::{
    attach_backend, extended_enabled, pick_port, resolve_node_bin, start_funded_chain, Funder,
    Lightwalletd, RegtestNode, Zebrad, Zecd, ZecdConfig,
};

const FUND_TIMEOUT: Duration = Duration::from_secs(240);
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);
const OP_TIMEOUT: Duration = Duration::from_secs(600);

/// Transparent fan-out: 2 funder sends x 28 t-outputs x 0.02 ZEC = 56 UTXOs (> the default
/// transparent_limit of 50). Transparent outputs cost the funder no shielded actions, so these
/// are cheap proofs.
const T_FANOUT_TXS: usize = 2;
const T_FANOUT_OUTPUTS: usize = 28;
const T_FANOUT_ZATS: u64 = 2_000_000; // 0.02 ZEC

/// Shielded fan-out: 1 funder send x 12 UA-outputs x 0.005 ZEC = 12 notes.
///
/// Sized to the *behaviour* under test rather than to zcashd's default constants: what the note
/// merges below have to prove is that an explicit `shielded_limit` binds and takes the manual
/// limited-selection path, that a non-binding call rides `propose_send_max` instead, and that
/// the two converge to a single note. None of that needs a large note set - only more eligible
/// notes than the binding limit - and every note here is paid for twice in Orchard actions,
/// once when the funder mints it and again when a merge spends it. The wallet was fanned out to
/// 64 notes (2 x 32) merged at a limit of 40 until 2026-08, which put ~131 actions of proving on
/// the PR tier for assertions that 12 notes make identically. The case that genuinely needs the
/// big set - zcashd's 200-note default `shielded_limit` binding - is the extended-tier test
/// below, which is where it was already placed for the same reason.
const N_FANOUT_TXS: usize = 1;
const N_FANOUT_OUTPUTS: usize = 12;
const N_FANOUT_ZATS: u64 = 500_000; // 0.005 ZEC

/// The explicit `shielded_limit` for the first note merge: binds (14 eligible > 8), so it takes
/// the manual limited-selection path and bounds this binary's biggest proof; the follow-up
/// defaults call then fits the unlimited `propose_send_max` path. Keep it strictly below the
/// eligible count (`N_FANOUT_TXS * N_FANOUT_OUTPUTS` plus the two t->z merge outputs) or round
/// 1 stops exercising the limited path at all.
const NOTE_MERGE_LIMIT: usize = 8;

/// Mine past the untrusted confirmations depth (ZIP-315 default 10) and wait for zecd to scan
/// it: the fan-out lands on the wallet's own *external* addresses, which the confirmations
/// policy treats as third-party receives, and `z_mergetoaddress` has no `minconf` argument
/// (zcashd has none either) - so merge eligibility always means "10+ confirmations" here.
async fn confirm_untrusted(zebrad: &Zebrad, zecd: &Zecd) {
    zebrad
        .generate_blocks(12)
        .await
        .expect("mine past the untrusted depth");
    let tip = zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebra getblockcount")
        .as_u64()
        .expect("tip height");
    zecd.wait_until_synced(tip, SYNC_TIMEOUT)
        .await
        .expect("zecd scans to the chain tip");
}

/// Drive a merge/send opid to success via `z_waitforoperation` and return the result object.
async fn await_op(zecd: &Zecd, opid: &str, what: &str) -> Value {
    assert!(opid.starts_with("opid-"), "{what}: opid shape: {opid}");
    let waited = zecd
        .call(
            "z_waitforoperation",
            json!([opid, OP_TIMEOUT.as_secs() as i64]),
        )
        .await
        .expect("z_waitforoperation");
    assert_eq!(
        waited["finished"], true,
        "{what}: waiting on {opid} timed out: {waited}"
    );
    assert_eq!(waited["status"], "success", "{what} failed: {waited}");
    waited["result"].clone()
}

/// Count the wallet's confirmed unspent outputs, split (transparent, shielded) by address shape.
async fn unspent_counts(zecd: &Zecd) -> (usize, usize) {
    let lu = zecd
        .call("listunspent", json!([1]))
        .await
        .expect("listunspent");
    let entries = lu.as_array().expect("listunspent array");
    let transparent = entries
        .iter()
        .filter(|n| n["address"].as_str().unwrap_or("").starts_with("tm"))
        .count();
    (transparent, entries.len() - transparent)
}

/// Bring up chain + funder + a transparent-enabled zecd (Orchard action cap lifted - the merge
/// proofs exceed the default 50 in the extended test) and wait for readiness. The returned
/// [`Lightwalletd`] guard (Some on the lwd leg) must be HELD for the test's lifetime - dropping
/// it kills the light upstream, which is exactly the bug the first lwd CI run hit when this
/// helper bound it locally.
async fn merge_stack(zebrad_bin: &std::path::Path) -> (Zebrad, Funder, Zecd, Option<Lightwalletd>) {
    let (zebrad, funder) = start_funded_chain(zebrad_bin)
        .await
        .expect("bring up a funded regtest chain");
    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.transparent = true;
    // Only wide enough for one fan-out round's issuance: `funder_fanout_round` mines and syncs
    // before the next round starts, so the longest run of consecutive *unfunded* exposed
    // addresses is T_FANOUT_OUTPUTS (28), not the full 56. Width is not free - recording a
    // transparent receive re-derives the whole gap window per involved address, so the cost of
    // ingesting one 28-output fan-out tx grows with this limit (zecd says so itself while doing
    // it: "recording transparent receives from block scan (each receive re-derives the gap
    // window)"). At 80 that ingest measured ~47s per round against ~78s for the funder's send.
    cfg.transparent_gap_limit = Some(40);
    cfg.orchard_action_limit = Some(0);
    let zecd_lwd = attach_backend(&mut cfg, zebrad.rpc_port)
        .await
        .expect("attach zecd backend");
    let zecd = Zecd::start(&cfg).await.expect("start zecd");
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
        assert!(Instant::now() < deadline, "zecd never reached ready");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    (zebrad, funder, zecd, zecd_lwd)
}

/// One funder fan-out round: pay `zats` to `count` fresh zecd addresses of the given type in a
/// single multi-output `z_sendmany`, then confirm it and let the funder's change reconfirm
/// (its config runs 1-conf trust) so the next round has spendable notes.
async fn funder_fanout_round(
    zebrad: &Zebrad,
    funder: &Funder,
    zecd: &Zecd,
    count: usize,
    zats: u64,
    transparent: bool,
) {
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        let params = if transparent {
            json!(["", "transparent"])
        } else {
            json!([])
        };
        let addr = zecd
            .call("getnewaddress", params)
            .await
            .expect("getnewaddress")
            .as_str()
            .expect("address string")
            .to_string();
        outputs.push((addr, zats));
    }
    funder
        .send_many(&outputs)
        .await
        .expect("funder fan-out send");
    zebrad
        .generate_blocks(2)
        .await
        .expect("confirm the fan-out round");
    funder
        .sync(zebrad)
        .await
        .expect("funder sync after the round");
}

#[tokio::test]
async fn regtest_mergetoaddress_consolidates_a_fragmented_wallet() {
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_mergetoaddress_consolidates_a_fragmented_wallet: set {} to run the \
             z_mergetoaddress e2e. The harness still compiled.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };
    let t0 = Instant::now();
    let phase = |name: &str| eprintln!("[merge-e2e {:>4}s] {name}", t0.elapsed().as_secs());

    // 1. Stack + funder-built fixture: 56 transparent UTXOs and exactly 64 notes, none of them
    //    created by the wallet under test.
    let (zebrad, funder, zecd, _zecd_lwd) = merge_stack(&zebrad_bin).await;
    let funder_taddr = funder.transparent_address().to_string();
    let own_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress UA")
        .as_str()
        .expect("address string")
        .to_string();
    phase("stack up");
    for _ in 0..T_FANOUT_TXS {
        funder_fanout_round(
            &zebrad,
            &funder,
            &zecd,
            T_FANOUT_OUTPUTS,
            T_FANOUT_ZATS,
            true,
        )
        .await;
    }
    phase("transparent fan-out done");
    for _ in 0..N_FANOUT_TXS {
        funder_fanout_round(
            &zebrad,
            &funder,
            &zecd,
            N_FANOUT_OUTPUTS,
            N_FANOUT_ZATS,
            false,
        )
        .await;
    }
    confirm_untrusted(&zebrad, &zecd).await;
    let (t_count, z_count) = unspent_counts(&zecd).await;
    assert_eq!(
        t_count,
        T_FANOUT_TXS * T_FANOUT_OUTPUTS,
        "the fan-out produced the full transparent set"
    );
    assert_eq!(
        z_count,
        N_FANOUT_TXS * N_FANOUT_OUTPUTS,
        "the fan-out produced the full note set (funder-paid, so nothing recycled it)"
    );
    phase(&format!("fragmented: {t_count} UTXOs, {z_count} notes"));

    // 2. Refusal matrix, all synchronous.
    let err = zecd
        .call("z_mergetoaddress", json!([["ANY_TADDR"], own_ua]))
        .await
        .expect_err("a transparent source needs AllowRevealedSenders");
    assert_eq!(err.code(), Some(-4), "default policy -> -4: {err}");
    assert!(
        format!("{err}").contains("Insufficient privacy policy"),
        "the -4 names the gate: {err}"
    );
    let err = zecd
        .call(
            "z_mergetoaddress",
            json!([
                ["ANY_TADDR"],
                funder_taddr,
                null,
                null,
                null,
                null,
                "AllowRevealedSenders"
            ]),
        )
        .await
        .expect_err("a fully transparent merge needs AllowFullyTransparent");
    assert_eq!(err.code(), Some(-4), "t->t under senders-only -> -4: {err}");
    let err = zecd
        .call(
            "z_mergetoaddress",
            json!([
                [funder_taddr],
                own_ua,
                null,
                null,
                null,
                null,
                "AllowRevealedSenders"
            ]),
        )
        .await
        .expect_err("a foreign source address is rejected");
    assert_eq!(err.code(), Some(-5), "foreign source -> -5: {err}");
    let err = zecd
        .call(
            "z_mergetoaddress",
            json!([
                ["ANY_TADDR", "ANY_ORCHARD"],
                own_ua,
                null,
                null,
                null,
                null,
                "AllowRevealedSenders"
            ]),
        )
        .await
        .expect_err("mixed source classes are rejected");
    assert_eq!(err.code(), Some(-8), "mixed classes -> -8: {err}");
    phase("refusal matrix done");

    // 3. t→t merge with an explicit limit: 5 smallest UTXOs into one output at an own
    //    t-address, transparent end to end (no proof at all), under AllowFullyTransparent.
    let own_taddr = zecd
        .call("getnewaddress", json!(["", "transparent"]))
        .await
        .expect("getnewaddress transparent")
        .as_str()
        .expect("address string")
        .to_string();
    let resp = zecd
        .call(
            "z_mergetoaddress",
            json!([
                ["ANY_TADDR"],
                own_taddr,
                null,
                5,
                null,
                null,
                "AllowFullyTransparent"
            ]),
        )
        .await
        .expect("t->t merge");
    assert_eq!(
        resp["mergingUTXOs"],
        json!(5),
        "explicit limit binds: {resp}"
    );
    assert_eq!(
        resp["remainingUTXOs"],
        json!(t_count as u64 - 5),
        "the remainder is reported: {resp}"
    );
    assert_eq!(resp["mergingNotes"], json!(0), "no note stats on a t merge");
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "t->t merge").await;
    confirm_untrusted(&zebrad, &zecd).await;
    let (t_after_t2t, _) = unspent_counts(&zecd).await;
    assert_eq!(
        t_after_t2t,
        t_count - 5 + 1,
        "5 UTXOs became 1 (kept transparent)"
    );
    phase("t->t merge done");

    // 4. t→z merges at the default transparent_limit (50): the first call reports exactly 50
    //    merging and the rest remaining; the second call drains the remainder. Values are
    //    consistent across rounds: round 1's remaining is exactly round 2's merging.
    let resp = zecd
        .call(
            "z_mergetoaddress",
            json!([
                ["ANY_TADDR"],
                own_ua,
                null,
                null,
                null,
                null,
                "AllowRevealedSenders"
            ]),
        )
        .await
        .expect("t->z merge round 1");
    assert_eq!(
        resp["mergingUTXOs"],
        json!(50),
        "the default transparent_limit is 50: {resp}"
    );
    assert_eq!(
        resp["remainingUTXOs"],
        json!(t_after_t2t as u64 - 50),
        "the remainder is reported: {resp}"
    );
    let remaining_v = resp["remainingTransparentValue"].as_f64().expect("value");
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "t->z merge round 1").await;
    confirm_untrusted(&zebrad, &zecd).await;
    let resp = zecd
        .call(
            "z_mergetoaddress",
            json!([
                ["ANY_TADDR"],
                own_ua,
                null,
                null,
                null,
                null,
                "AllowRevealedSenders"
            ]),
        )
        .await
        .expect("t->z merge round 2");
    assert_eq!(
        resp["mergingUTXOs"],
        json!(t_after_t2t as u64 - 50),
        "round 2 picks up the remainder: {resp}"
    );
    assert_eq!(
        resp["remainingUTXOs"],
        json!(0),
        "nothing left after: {resp}"
    );
    let merging_v2 = resp["mergingTransparentValue"].as_f64().expect("value");
    assert!(
        (remaining_v - merging_v2).abs() < 1e-8,
        "round 1's remaining value is exactly round 2's merging value \
         ({remaining_v} vs {merging_v2})"
    );
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "t->z merge round 2").await;
    confirm_untrusted(&zebrad, &zecd).await;
    let (t_final, z_with_merge_outputs) = unspent_counts(&zecd).await;
    assert_eq!(t_final, 0, "every transparent UTXO has been shielded");
    assert_eq!(
        z_with_merge_outputs,
        z_count + 2,
        "the two t->z merges each minted one shielded output"
    );
    phase("t->z merges done (0 UTXOs left)");

    // 5. Note merges. Round 1: an explicit shielded_limit that binds (8 < 14 eligible) takes
    //    the manual limited-selection path and reports the remainder.
    let resp = zecd
        .call(
            "z_mergetoaddress",
            json!([["ANY_ORCHARD"], own_ua, null, null, NOTE_MERGE_LIMIT]),
        )
        .await
        .expect("note merge round 1");
    assert_eq!(
        resp["mergingNotes"],
        json!(NOTE_MERGE_LIMIT as u64),
        "the explicit shielded_limit binds: {resp}"
    );
    assert_eq!(
        resp["remainingNotes"],
        json!((z_with_merge_outputs - NOTE_MERGE_LIMIT) as u64),
        "the remainder is reported: {resp}"
    );
    assert_eq!(
        resp["mergingUTXOs"],
        json!(0),
        "no UTXO stats on a note merge"
    );
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "note merge round 1").await;
    confirm_untrusted(&zebrad, &zecd).await;

    // Round 2: defaults (200 does not bind against the handful left) ride librustzcash's
    // `propose_send_max` path wholesale, with a memo on the merged output for coverage - and
    // because round 1's own output is back in the eligible set, this converges the wallet to a
    // single note.
    let memo_hex = "6d6572676564"; // "merged"
    let resp = zecd
        .call(
            "z_mergetoaddress",
            json!([["ANY_ORCHARD"], own_ua, null, null, null, memo_hex]),
        )
        .await
        .expect("note merge round 2");
    assert_eq!(
        resp["mergingNotes"],
        json!((z_with_merge_outputs - NOTE_MERGE_LIMIT + 1) as u64),
        "round 2 merges the remainder plus round 1's output: {resp}"
    );
    assert_eq!(resp["remainingNotes"], json!(0), "{resp}");
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "note merge round 2").await;
    confirm_untrusted(&zebrad, &zecd).await;
    let (t_end, z_end) = unspent_counts(&zecd).await;
    assert_eq!(t_end, 0);
    assert_eq!(
        z_end, 1,
        "the whole fragmented wallet consolidated to one note"
    );
    phase("note merges done (1 note left)");

    // 6. z→t finale: sweep that note to the funder's t-address under the default policy (the
    //    deshielding direction needs no opt-in), amountless - the exact "send all" that
    //    z_sendmany cannot express without fee arithmetic.
    let resp = zecd
        .call("z_mergetoaddress", json!([["ANY_ORCHARD"], funder_taddr]))
        .await
        .expect("z->t sweep");
    assert_eq!(resp["mergingNotes"], json!(1), "{resp}");
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "z->t sweep").await;
    confirm_untrusted(&zebrad, &zecd).await;
    let bal = zecd
        .call("getbalance", json!([]))
        .await
        .expect("getbalance")
        .as_f64()
        .expect("balance");
    assert!(bal < 1e-8, "the sweep emptied the wallet (got {bal})");
    phase("z->t sweep done (wallet empty)");

    drop(zecd);
    // `zebrad` and `funder` clean up on drop.
}

/// The >200-notes case: a defaults call against a 225-note wallet reports exactly
/// `mergingNotes: 200` (zcashd's default `shielded_limit` binding on the manual selection
/// path), and the follow-up drains the rest. ~200 actions of proving on both the fan-out and
/// the merge sides puts this well past the PR tier's envelope, so it runs on the extended tier
/// (`ZECD_REGTEST_EXTENDED=1`: weekly schedule + workflow dispatch), like the other heavy e2es.
#[tokio::test]
async fn regtest_mergetoaddress_default_shielded_limit() {
    if !extended_enabled() {
        eprintln!(
            "SKIP regtest_mergetoaddress_default_shielded_limit: set ZECD_REGTEST_EXTENDED=1 to \
             run the extended tier."
        );
        return;
    }
    let Some(zebrad_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_mergetoaddress_default_shielded_limit: set {} to run the extended \
             z_mergetoaddress e2e. The harness still compiled.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };
    let t0 = Instant::now();
    let phase = |name: &str| eprintln!("[merge-ext {:>4}s] {name}", t0.elapsed().as_secs());

    // 225 notes across five 45-output funder sends (45 payments + change splits stays under
    // the released funder's default 50-action cap).
    let (zebrad, funder, zecd, _zecd_lwd) = merge_stack(&zebrad_bin).await;
    let own_ua = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("getnewaddress UA")
        .as_str()
        .expect("address string")
        .to_string();
    for _ in 0..5 {
        funder_fanout_round(&zebrad, &funder, &zecd, 45, N_FANOUT_ZATS, false).await;
    }
    confirm_untrusted(&zebrad, &zecd).await;
    let (_, z_count) = unspent_counts(&zecd).await;
    assert_eq!(
        z_count, 225,
        "the funder fan-out produced the full note set"
    );
    phase("fragmented: 225 notes");

    // Defaults: the 200-note default shielded_limit binds against 225 eligible.
    let resp = zecd
        .call("z_mergetoaddress", json!([["ANY_ORCHARD"], own_ua]))
        .await
        .expect("default-limit note merge");
    assert_eq!(
        resp["mergingNotes"],
        json!(200),
        "zcashd's default shielded_limit is 200: {resp}"
    );
    assert_eq!(resp["remainingNotes"], json!(25), "{resp}");
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "default-limit note merge").await;
    confirm_untrusted(&zebrad, &zecd).await;
    phase("200-note merge done");

    // The follow-up drains the remainder plus the first round's output: one note left.
    let resp = zecd
        .call("z_mergetoaddress", json!([["ANY_ORCHARD"], own_ua]))
        .await
        .expect("drain merge");
    assert_eq!(resp["mergingNotes"], json!(26), "{resp}");
    assert_eq!(resp["remainingNotes"], json!(0), "{resp}");
    let opid = resp["opid"].as_str().expect("opid").to_string();
    await_op(&zecd, &opid, "drain merge").await;
    confirm_untrusted(&zebrad, &zecd).await;
    let (_, z_end) = unspent_counts(&zecd).await;
    assert_eq!(z_end, 1, "225 notes converged to one");
    phase("converged to 1 note");

    drop(zecd);
}
