//! Fleet end-to-end: many independent view wallets monitored by one daemon, scanned in shards.
//!
//! This is the live counterpart of the offline shard test in `wallet::regtest_tests`. That one
//! proves the routing (N wallets, one actor, N distinct accounts, no cross-wallet leakage) against
//! a database it built by hand. This one proves the thing that actually matters to an operator:
//! that a real chain, a real funder and a real daemon put each wallet's money in that wallet and
//! nobody else's - and that the daemon does it with a handful of scans rather than one per wallet.
//!
//! Three properties, in one funded chain:
//!
//! 1. **Isolation.** Every wallet's balance, history and `listunspent` show its own payment and
//!    none of the others', across shard boundaries and within a single shard. All of these wallets
//!    read the *same* database file as their shard-mates, so this is where an account-scoping
//!    mistake would show up as one customer seeing another's funds.
//! 2. **One transaction, many wallets.** A single funder `z_sendmany` paying several fleet wallets
//!    at once is credited to each of them exactly once - the shape an exchange sweep actually has,
//!    and the one where a shared scan could plausibly double-count or drop an output.
//! 3. **Sharing.** The wallets are spread over several shards, and every shard is caught up: the
//!    daemon scanned the chain a few times, not once per wallet.
//!
//! Standard tier (runs on every PR), zebra-backed. Needs a funder, so it skips cleanly without one.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{
    pick_port, provision_view_wallets, resolve_node_bin, start_funded_chain, RegtestNode, RpcError,
    Zecd, ZecdConfig,
};

/// How many view wallets the fleet holds.
///
/// Sized to be honest about the mechanism rather than to be a load test: enough wallets to span
/// several shards and to make a per-wallet cost visible, few enough that provisioning them (a real
/// `zecd init` apiece) stays a fraction of the suite's runtime. The offline test in the main crate
/// carries a larger set, and the production bound is `[fleet] shard_size`, not this.
const FLEET_SIZE: usize = 12;

/// Wallets per shard database. Deliberately smaller than `FLEET_SIZE` so the fleet spans several
/// shards: a single-shard fleet would never exercise placement, and would hide a bug where every
/// wallet's reads accidentally worked because they all shared one database.
const SHARD_SIZE: usize = 5;

/// Zatoshis paid to wallet `i`. Distinct per wallet, so a balance landing in the wrong wallet is a
/// wrong *number* rather than a coincidence that happens to match.
fn payment_for(index: usize) -> u64 {
    1_000_000 + (index as u64 + 1) * 100_000
}

const SYNC_TIMEOUT: Duration = Duration::from_secs(180);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regtest_fleet_many_view_wallets_are_scanned_together_and_stay_isolated() {
    let Some(node_bin) = resolve_node_bin() else {
        eprintln!(
            "SKIP regtest_fleet: set {}. The harness still compiled and linked.",
            RegtestNode::from_env().bin_env()
        );
        return;
    };

    let (zebrad, funder) = match start_funded_chain(&node_bin).await {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("SKIP regtest_fleet: could not bring up a funded chain: {e:#}");
            return;
        }
    };

    // Provision the fleet: independent wallets whose *viewing* keys are all the daemon gets. The
    // spending sides are throwaway datadirs it never sees, which is the real deployment shape.
    let wallets = provision_view_wallets(zebrad.rpc_port, FLEET_SIZE, 2)
        .await
        .expect("provision the view wallets");
    assert_eq!(wallets.len(), FLEET_SIZE);

    let mut cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    cfg.fleet = wallets.clone();
    cfg.fleet_shard_size = Some(SHARD_SIZE);
    cfg.birthday = Some(2);
    let zecd = Zecd::start(&cfg).await.expect("start zecd with a fleet");
    zecd.wait_until_synced_to_node(&zebrad, SYNC_TIMEOUT)
        .await
        .expect("zecd catches up");

    // Every fleet wallet is served, alongside the daemon's own spending wallet. `listwallets` is
    // the operator's view of the fleet, so it must name all of them.
    let listed: BTreeSet<String> = zecd
        .call("listwallets", json!([]))
        .await
        .expect("listwallets")
        .as_array()
        .expect("listwallets returns an array")
        .iter()
        .map(|v| v.as_str().expect("wallet name").to_string())
        .collect();
    assert!(listed.contains("default"), "the spending wallet is served");
    for wallet in &wallets {
        assert!(
            listed.contains(&wallet.name),
            "fleet wallet '{}' is not served; listwallets = {listed:?}",
            wallet.name
        );
    }

    // Every fleet wallet is watch-only - the fleet monitors, it does not spend.
    for wallet in &wallets {
        let info = zecd
            .call_wallet(&wallet.name, "getwalletinfo", json!([]))
            .await
            .expect("getwalletinfo");
        assert_eq!(
            info["private_keys_enabled"],
            json!(false),
            "fleet wallet '{}' must be watch-only",
            wallet.name
        );
    }

    // --- Property 2: one transaction, many wallets ---------------------------------------
    //
    // Pay the whole fleet in as few transactions as the funder's action cap allows, so several
    // wallets share a transaction. A shared scan sees each of these outputs once, against every
    // key at once; crediting the wrong wallet, or crediting one twice, shows up below as a wrong
    // balance rather than as a crash.
    //
    // Chunked because the funder is a released zecd with a default 50-action cap per send, and
    // its change must confirm between rounds before it can fund the next.
    for chunk in wallets.chunks(6) {
        let outputs: Vec<(String, u64)> = chunk
            .iter()
            .map(|w| {
                let index = wallets
                    .iter()
                    .position(|x| x.name == w.name)
                    .expect("known");
                (w.address.clone(), payment_for(index))
            })
            .collect();
        funder
            .send_many(&outputs)
            .await
            .expect("funder pays a batch of fleet wallets");
        zebrad.generate_blocks(2).await.expect("mine the payments");
        funder.sync(&zebrad).await.expect("funder follows the tip");
    }
    // Past the untrusted-note confirmation depth. These payments come from *outside* the wallet,
    // so ZIP-315's untrusted policy (10 confirmations, zecd's default) governs when they count as
    // spendable - and `getbalance` reports spendable value. Mining only a couple of blocks would
    // read as a balance of zero and say nothing about whether the scan worked.
    zebrad
        .generate_blocks(12)
        .await
        .expect("confirm the payments past the untrusted depth");
    // Wait per wallet, not on the daemon as a whole. Each shard is its own scan domain with its
    // own actor, so the spending wallet reaching the tip says nothing about the shards - waiting
    // only on it would make every assertion below a race.
    let tip = node_height(&zebrad).await;
    wait_for_fleet(&zecd, &wallets, tip).await;

    // --- Property 1: isolation ------------------------------------------------------------
    //
    // Each wallet holds exactly its own payment. These wallets share database files with their
    // shard-mates, so an unscoped read would show a shard's whole balance here, and a routing
    // mistake would show a neighbour's.
    for (index, wallet) in wallets.iter().enumerate() {
        let expected = payment_for(index);

        let balance = zecd
            .call_wallet(&wallet.name, "getbalance", json!([]))
            .await
            .expect("getbalance");
        let zats = zec_to_zats(&balance);
        assert_eq!(
            zats, expected,
            "wallet '{}' should hold exactly its own payment ({expected} zats), got {zats}",
            wallet.name
        );

        // One unspent note, at this wallet's own address: the payment, and nothing belonging to
        // a shard-mate.
        let unspent = zecd
            .call_wallet(&wallet.name, "listunspent", json!([0]))
            .await
            .expect("listunspent");
        let notes = unspent.as_array().expect("listunspent returns an array");
        assert_eq!(
            notes.len(),
            1,
            "wallet '{}' should see exactly one note, got {notes:?}",
            wallet.name
        );
        assert_eq!(
            zec_to_zats(&notes[0]["amount"]),
            expected,
            "wallet '{}' note value",
            wallet.name
        );

        // History likewise: one receive, of this wallet's amount.
        let txs = zecd
            .call_wallet(&wallet.name, "listtransactions", json!([]))
            .await
            .expect("listtransactions");
        let entries = txs.as_array().expect("listtransactions returns an array");
        assert_eq!(
            entries.len(),
            1,
            "wallet '{}' should have exactly one history entry, got {entries:?}",
            wallet.name
        );
        assert_eq!(entries[0]["category"], json!("receive"));
        assert_eq!(
            zec_to_zats(&entries[0]["amount"]),
            expected,
            "wallet '{}' history amount",
            wallet.name
        );
    }

    // Addresses are per-wallet too: `getnewaddress` on a shared database must derive from the
    // asking wallet's account, not the shard's first. Distinct addresses across the fleet is the
    // observable form of that.
    let mut issued = BTreeSet::new();
    for wallet in &wallets {
        let address = zecd
            .call_wallet(&wallet.name, "getnewaddress", json!([]))
            .await
            .expect("getnewaddress")
            .as_str()
            .expect("an address")
            .to_string();
        assert!(
            issued.insert(address.clone()),
            "wallet '{}' was handed an address another fleet wallet already has",
            wallet.name
        );
        // And it belongs to the wallet that asked for it.
        let info = zecd
            .call_wallet(&wallet.name, "getaddressinfo", json!([address.clone()]))
            .await
            .expect("getaddressinfo");
        assert_eq!(
            info["ismine"],
            json!(true),
            "wallet '{}' must own the address it just issued",
            wallet.name
        );
        // A shard-mate must not claim it. Picking the *other* wallets keeps this meaningful
        // whichever shard the pair landed in.
        for other in wallets.iter().filter(|w| w.name != wallet.name) {
            let info = zecd
                .call_wallet(&other.name, "getaddressinfo", json!([address.clone()]))
                .await
                .expect("getaddressinfo");
            assert_eq!(
                info["ismine"],
                json!(false),
                "wallet '{}' must not claim '{}'s address",
                other.name,
                wallet.name
            );
        }
    }

    // --- Property 1b: watch-only refusal ---------------------------------------------------
    //
    // A fleet wallet holds no spending material, so a send must fail with Bitcoin Core's exact
    // watch-only refusal - the same -4 an `init --ufvk` wallet returns - not the conventional
    // actor's "account is not ready" bootstrap message, which describes a keys.toml/unlock state
    // a shard does not have.
    {
        let wallet = &wallets[0];
        let addr = zecd
            .call_wallet(&wallet.name, "getnewaddress", json!([]))
            .await
            .expect("a watch-only wallet still derives addresses");
        let err = zecd
            .call_wallet(
                &wallet.name,
                "sendtoaddress",
                json!([addr.as_str().expect("address string"), 0.1]),
            )
            .await
            .expect_err("a fleet wallet must refuse to send");
        match err {
            RpcError::Rpc { code, message } => {
                assert_eq!(code, -4, "Core's wallet error code, got: {message}");
                assert!(
                    message.contains("Private keys are disabled"),
                    "Core's watch-only refusal, got: {message}"
                );
            }
            other => panic!("expected an RPC-level refusal, got {other:?}"),
        }
    }

    // --- Property 3: sharing ---------------------------------------------------------------
    //
    // The fleet is spread over several shard databases, and each one is caught up. The scan work
    // therefore scaled with shards, not with wallets - which is the whole point of the design.
    let shard_dirs = std::fs::read_dir(zecd.datadir().join("fleet"))
        .expect("the fleet directory exists")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .count();
    let expected_shards = FLEET_SIZE.div_ceil(SHARD_SIZE);
    assert_eq!(
        shard_dirs, expected_shards,
        "{FLEET_SIZE} wallets at shard_size {SHARD_SIZE} should occupy {expected_shards} shards"
    );

    // And each wallet's own view agrees the chain is scanned - a shard that silently stopped
    // would show here as a wallet stuck below the tip.
    for wallet in &wallets {
        let count = zecd
            .call_wallet(&wallet.name, "getblockcount", json!([]))
            .await
            .expect("getblockcount")
            .as_u64()
            .expect("a height");
        assert_eq!(
            count, tip,
            "wallet '{}' reports height {count}, chain tip is {tip}",
            wallet.name
        );
    }

    // --- Runtime onboarding ------------------------------------------------------------------
    //
    // A fleet that can only grow by editing a config file and restarting is not a fleet: every
    // arrival would cost every wallet in the daemon a stop and a re-sync. `createwallet` places a
    // new view wallet into a shard - opening one if none has room - and serves it immediately.
    let newcomer = provision_view_wallets(zebrad.rpc_port, 1, 2)
        .await
        .expect("provision a late arrival")
        .pop()
        .expect("one wallet");
    let created = zecd
        .call(
            "createwallet",
            json!([
                "late-arrival",
                true,
                null,
                null,
                null,
                null,
                null,
                null,
                { "ufvk": newcomer.ufvk, "birthday": 2 }
            ]),
        )
        .await
        .expect("createwallet onboards a view wallet");
    assert_eq!(created["name"], json!("late-arrival"));

    // It is served straight away, before it has scanned anything.
    let info = zecd
        .call_wallet("late-arrival", "getwalletinfo", json!([]))
        .await
        .expect("the new wallet answers immediately");
    assert_eq!(info["private_keys_enabled"], json!(false));

    // Onboarding is idempotent-proof: the same name twice is refused rather than served by two
    // accounts, which would leave one of them silently unreachable.
    let again = zecd
        .call(
            "createwallet",
            json!(["late-arrival", true, null, null, null, null, null, null,
                   { "ufvk": newcomer.ufvk, "birthday": 2 }]),
        )
        .await;
    assert!(
        again.is_err(),
        "createwallet must refuse a name that is already loaded, got {again:?}"
    );

    // And it actually scans: pay it, and the money arrives in it and nowhere else.
    let late_payment = 4_200_000;
    funder
        .send(&newcomer.address, late_payment)
        .await
        .expect("funder pays the late arrival");
    zebrad
        .generate_blocks(12)
        .await
        .expect("mine the late payment past the untrusted depth");
    funder.sync(&zebrad).await.expect("funder follows the tip");
    let tip = node_height(&zebrad).await;
    let late = zecd_regtest_harness::ViewWallet {
        name: "late-arrival".to_string(),
        ..newcomer.clone()
    };
    wait_for_fleet(&zecd, std::slice::from_ref(&late), tip).await;
    assert_eq!(
        zec_to_zats(
            &zecd
                .call_wallet("late-arrival", "getbalance", json!([]))
                .await
                .expect("getbalance")
        ),
        late_payment,
        "the wallet onboarded at runtime must be credited its payment"
    );
    // The wallets that were already there are undisturbed - onboarding must not have rewound a
    // shard they live in and lost their balances.
    for (index, wallet) in wallets.iter().enumerate() {
        assert_eq!(
            zec_to_zats(
                &zecd
                    .call_wallet(&wallet.name, "getbalance", json!([]))
                    .await
                    .expect("getbalance")
            ),
            payment_for(index),
            "wallet '{}' lost its balance when a new wallet was onboarded",
            wallet.name
        );
    }

    // `listwalletdir` reports what is provisioned on disk, which is now the whole fleet plus the
    // newcomer - the answer an operator needs when a name is missing from `listwallets`.
    let on_disk: BTreeSet<String> = zecd
        .call("listwalletdir", json!([]))
        .await
        .expect("listwalletdir")["wallets"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|w| w["name"].as_str().expect("a name").to_string())
        .collect();
    assert!(on_disk.contains("late-arrival"));
    for wallet in &wallets {
        assert!(
            on_disk.contains(&wallet.name),
            "{} is provisioned",
            wallet.name
        );
    }

    // Unload stops serving it without deleting anything, and load brings it back - with its
    // balance, since its account never left its shard.
    zecd.call("unloadwallet", json!(["late-arrival"]))
        .await
        .expect("unloadwallet");
    assert!(
        zecd.call_wallet("late-arrival", "getwalletinfo", json!([]))
            .await
            .is_err(),
        "an unloaded wallet must not be served"
    );
    zecd.call("loadwallet", json!(["late-arrival"]))
        .await
        .expect("loadwallet");
    assert_eq!(
        zec_to_zats(
            &zecd
                .call_wallet("late-arrival", "getbalance", json!([]))
                .await
                .expect("getbalance after reload")
        ),
        late_payment,
        "a reloaded wallet keeps its balance - unloading deletes nothing"
    );

    // A restart must adopt every account from its shard database rather than re-import it: the
    // manifest is idempotent, and re-importing would rewind the shard and rescan the fleet.
    let mut zecd = zecd;
    zecd.stop_keeping_datadir()
        .await
        .expect("stop the daemon cleanly");
    zecd.respawn().await.expect("restart the daemon");
    let mut after_restart = wallets.clone();
    after_restart.push(zecd_regtest_harness::ViewWallet {
        name: "late-arrival".to_string(),
        ..newcomer.clone()
    });
    wait_for_fleet(&zecd, &after_restart, node_height(&zebrad).await).await;
    for (index, wallet) in wallets.iter().enumerate() {
        let balance = zecd
            .call_wallet(&wallet.name, "getbalance", json!([]))
            .await
            .expect("getbalance after restart");
        assert_eq!(
            zec_to_zats(&balance),
            payment_for(index),
            "wallet '{}' lost its balance across a restart",
            wallet.name
        );
    }
    // The runtime-onboarded wallet too: `createwallet` wrote its manifest, so a restart must load
    // it from disk like any other - and adopt its existing account rather than re-import it.
    assert_eq!(
        zec_to_zats(
            &zecd
                .call_wallet("late-arrival", "getbalance", json!([]))
                .await
                .expect("the runtime-onboarded wallet survives a restart")
        ),
        late_payment,
        "the wallet onboarded at runtime was not reloaded from its manifest"
    );
}

/// The node's current tip height.
async fn node_height(zebrad: &zecd_regtest_harness::Zebrad) -> u64 {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .expect("zebrad getblockcount")
        .as_u64()
        .expect("a height")
}

/// Block until every fleet wallet has *scanned* to `height`.
///
/// `waitforblockheight` per wallet, which is the daemon's own answer to "has this wallet caught
/// up?" - and, routed at `/wallet/<name>`, it is answered by that wallet's shard actor rather than
/// by the daemon as a whole. A timeout is not an error on that RPC (it returns the current tip),
/// so the height it reports is asserted here.
async fn wait_for_fleet(zecd: &Zecd, wallets: &[zecd_regtest_harness::ViewWallet], height: u64) {
    for wallet in wallets {
        let reached = zecd
            .call_wallet(
                &wallet.name,
                "waitforblockheight",
                json!([height, SYNC_TIMEOUT.as_millis() as u64]),
            )
            .await
            .unwrap_or_else(|e| panic!("waitforblockheight for '{}': {e:?}", wallet.name));
        assert_eq!(
            reached["height"].as_u64(),
            Some(height),
            "wallet '{}' did not scan to {height} within {SYNC_TIMEOUT:?}",
            wallet.name
        );
    }
}

/// A decimal ZEC amount (as zecd emits it, an exact JSON number) in zatoshis.
fn zec_to_zats(value: &serde_json::Value) -> u64 {
    let text = value.to_string();
    let text = text.trim_matches('"');
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let frac = format!("{frac:0<8}");
    let whole: u64 = whole
        .parse()
        .unwrap_or_else(|_| panic!("bad ZEC value {text}"));
    let frac: u64 = frac[..8]
        .parse()
        .unwrap_or_else(|_| panic!("bad ZEC fraction {text}"));
    whole * 100_000_000 + frac
}
