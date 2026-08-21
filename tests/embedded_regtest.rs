//! Live end-to-end check of the embedded path: `init::init_wallet` -> `NodeBuilder::start` ->
//! one TYPED call of each shape through `Node::call` -> `Node::shutdown`, against a throwaway
//! zebrad regtest chain. This is the typed client's only live coverage (the regtest harness is
//! deliberately a black-box driver of the binary over HTTP and cannot link the library), so it
//! walks shapes, not scenarios - the flows themselves stay covered by conformance + the
//! harness tier.
//!
//! `#[ignore]`d and self-skipping: it runs only with `ZECD_EMBEDDED_REGTEST=1` and a zebrad
//! binary in `ZEBRAD_BIN` (the same variable the regtest workflow exports):
//!
//! ```sh
//! ZECD_EMBEDDED_REGTEST=1 ZEBRAD_BIN=/path/to/zebrad \
//!     cargo test --release --test embedded_regtest -- --ignored --nocapture
//! ```
//!
//! The chain deliberately does NOT activate NU6.3 and the test does not set
//! `ZECD_REGTEST_NU63_HEIGHT`, so the two sides agree pre-NU6.3 (the harness's NU6.3-active
//! chains cover ironwood; this test is about the embedding seam, not the pool).

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A throwaway coinbase recipient (the harness's seed-miner address; nothing holds its key).
const MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";

/// The wallet the funded test restores. Regtest-only and valueless - the same phrase
/// `regtest_coinbase.rs` mines to, reused so both tests fund a wallet the repo already
/// publishes rather than each inventing a seed.
const FUNDED_MNEMONIC: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
midnight culture idea mountain fame park social drip bid doctor scatter glance defy moment stage";

/// Serializes the two end-to-end tests. Each spawns its own zebrad and builds proving keys, and
/// [`free_port`] hands back a port it has already released - so two running concurrently can
/// race onto the same one, and would contend for the machine besides. cargo runs a binary's
/// tests in parallel by default, so the guard is what makes that safe, rather than a
/// `--test-threads=1` every caller would have to remember to pass.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The regtest chain shape zecd's `network::regtest()` expects (the harness's template minus
/// the NU6.3 activation): NU5/NU6 from genesis, NU6.1/NU6.2 at height 4 with the ZIP-271
/// lockbox disbursement their activation block requires.
/// `miner_address` is where coinbase goes, and may be a unified address (zebra >= 6.0.0 mines
/// ZIP-213 shielded coinbase). The **lockbox disbursement** address deliberately stays
/// [`MINER_ADDRESS`] and is not parameterized: zebra parses it as a transparent address while
/// building the network parameters, so a unified address there aborts startup with
/// `hard-coded address must deserialize: Parse("unexpected payload length")` before the RPC
/// port ever opens - which presents as a bare connection-refused timeout.
fn zebrad_toml(net_port: u16, rpc_port: u16, cache_dir: &str, miner_address: &str) -> String {
    format!(
        r#"[network]
network = "Regtest"
listen_addr = "127.0.0.1:{net_port}"

[network.testnet_parameters]
disable_pow = true

[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = 4
"NU6.2" = 4

[[network.testnet_parameters.funding_streams]]
[network.testnet_parameters.funding_streams.height_range]
start = 1
end = 1_000_000
[[network.testnet_parameters.funding_streams.recipients]]
receiver = "Deferred"
numerator = 12
addresses = []

[[network.testnet_parameters.lockbox_disbursements]]
address = "{MINER_ADDRESS}"
amount = 1

[mining]
miner_address = "{miner_address}"

[state]
ephemeral = false
cache_dir = "{cache_dir}"

[rpc]
listen_addr = "127.0.0.1:{rpc_port}"
enable_cookie_auth = false
"#
    )
}

/// Kills the zebrad child on drop so a failed assertion never leaks a node.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Minimal std-only JSON-RPC 1.0 call against zebrad's cookie-less regtest endpoint - enough
/// to poll readiness and drive the Regtest-only `generate` RPC without an HTTP client crate.
fn zebra_rpc(port: u16, method: &str, params: &str) -> Result<serde_json::Value, String> {
    let body = format!(r#"{{"jsonrpc":"1.0","id":"t","method":"{method}","params":{params}}}"#);
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("set timeout");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("read: {e}"))?;
    let response = String::from_utf8_lossy(&response);
    let json_body = response
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| format!("no body in {response:?}"))?;
    let v: serde_json::Value =
        serde_json::from_str(json_body.trim()).map_err(|e| format!("parse: {e}"))?;
    if !v["error"].is_null() {
        return Err(format!("rpc error: {}", v["error"]));
    }
    Ok(v["result"].clone())
}

/// Start a throwaway zebrad regtest node mining to `miner_address`, and wait until it can
/// actually mine. Returns the child guard and its tempdir (both must outlive the caller) plus
/// the RPC port.
///
/// The readiness probe is `getblocktemplate`, NOT `getblockchaininfo`: the latter answers as
/// soon as the RPC server binds, while `generate` additionally needs zebra to consider its
/// state ready and refuses with "Zebra's state is empty, wait until it syncs to the chain tip"
/// until then. That gap is real - it failed in CI this way - and it widens under the load of
/// the harness binaries running alongside. The template endpoint is the precondition for
/// mining, so it is the thing to wait on (the regtest harness's own `wait_until_rpc_up` polls
/// it for exactly this reason).
async fn start_mineable_zebrad(
    zebrad_bin: &PathBuf,
    miner_address: &str,
) -> (KillOnDrop, tempfile::TempDir, u16) {
    let zebra_dir = tempfile::tempdir().expect("zebrad tempdir");
    let rpc_port = free_port();
    let net_port = free_port();
    let config_path = zebra_dir.path().join("zebrad.toml");
    let cache_dir = zebra_dir.path().join("state");
    std::fs::write(
        &config_path,
        zebrad_toml(
            net_port,
            rpc_port,
            &cache_dir.to_string_lossy(),
            miner_address,
        ),
    )
    .expect("write zebrad.toml");
    // Keep zebrad's output rather than discarding it: when it refuses a config it panics
    // *before* binding the RPC port, so the only symptom the poll below can see is a
    // connection refused for the full timeout. The log is what says why, so the failure
    // message carries its tail.
    let log_path = zebra_dir.path().join("zebrad.log");
    let log = std::fs::File::create(&log_path).expect("create zebrad log");
    let zebrad = KillOnDrop(
        Command::new(zebrad_bin)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::from(log.try_clone().expect("clone log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn zebrad"),
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match zebra_rpc(rpc_port, "getblocktemplate", "[]") {
            Ok(_) => break,
            Err(e) if Instant::now() < deadline => {
                eprintln!("waiting for zebrad to become mineable: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                let tail: Vec<&str> = log.lines().rev().take(25).collect();
                let tail: Vec<&str> = tail.into_iter().rev().collect();
                panic!(
                    "zebrad never became mineable: {e}\n--- zebrad log (last 25 lines) ---\n{}",
                    tail.join("\n")
                );
            }
        }
    }
    (zebrad, zebra_dir, rpc_port)
}

/// Mine `count` blocks, asserting they were actually produced.
fn mine(rpc_port: u16, count: u32) {
    let mined =
        zebra_rpc(rpc_port, "generate", &format!("[{count}]")).expect("mine the requested blocks");
    assert_eq!(
        mined.as_array().map(|a| a.len()),
        Some(count as usize),
        "{mined}"
    );
}

/// The env gate both tests share. `None` means skip.
fn zebrad_bin_or_skip(test: &str) -> Option<PathBuf> {
    if std::env::var("ZECD_EMBEDDED_REGTEST").as_deref() != Ok("1") {
        eprintln!("skipping {test}: set ZECD_EMBEDDED_REGTEST=1 (and ZEBRAD_BIN) to run");
        return None;
    }
    let bin = std::env::var("ZEBRAD_BIN")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file());
    if bin.is_none() {
        eprintln!("skipping {test}: ZEBRAD_BIN is unset or not a file");
    }
    bin
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn embedded_node_serves_typed_calls_end_to_end() {
    let _serial = SERIAL.lock().await;
    let Some(zebrad_bin) = zebrad_bin_or_skip("embedded_node_serves_typed_calls_end_to_end") else {
        return;
    };

    // Bring up a throwaway zebrad regtest node mining to an address nobody holds the key to,
    // so this wallet stays empty and the shape assertions below mean what they say.
    let (_zebrad, _zebra_dir, rpc_port) = start_mineable_zebrad(&zebrad_bin, MINER_ADDRESS).await;
    mine(rpc_port, 10);

    // The embedded path proper: clap-free config, the init core, the node facade.
    let datadir = tempfile::tempdir().expect("zecd datadir");
    let config = zecd::config::AppConfig::resolve_overrides(&zecd::config::ConfigOverrides {
        datadir: Some(datadir.path().to_path_buf()),
        regtest: true,
        server: Some(format!("zebra://127.0.0.1:{rpc_port}")),
        ..Default::default()
    })
    .expect("config resolves");

    let outcome = zecd::init::init_wallet(
        &config,
        zecd::init::InitOptions {
            wallet: "default".into(),
            key: zecd::init::InitKey::Generate,
            encryption: zecd::init::EncryptionInput::AgeIdentity,
            birthday: None,
        },
    )
    .await
    .expect("init_wallet");
    assert!(!outcome.watch_only && !outcome.encrypted);
    assert!(
        outcome.generated_mnemonic.is_some(),
        "a generated wallet returns its mnemonic"
    );

    let node = zecd::node::NodeBuilder::new(config)
        .start()
        .await
        .expect("node starts");
    let c = node.wallet(None);

    // One typed call per shape. First wait for the scan to catch up (the whole point of the
    // waitfor* family), then walk reads, a derivation, and the async-send surface.
    let tip = c
        .wait_for_block_height(10, Some(120_000))
        .await
        .expect("wait for scan");
    assert!(tip.height >= 10, "scanned to {} < 10", tip.height);

    let info = c.get_blockchain_info().await.expect("getblockchaininfo");
    assert_eq!(info.chain, "regtest");
    assert!(info.blocks >= 10);
    assert!(c.get_block_count().await.expect("getblockcount") >= 10);
    let best = c.get_best_block_hash().await.expect("getbestblockhash");
    let header = c.get_block_header(&best).await.expect("getblockheader");
    assert_eq!(header.hash, best);

    // A timed-out wait is not an error: it reports the current block.
    let timed_out = c
        .wait_for_block_height(9_999, Some(1))
        .await
        .expect("timeout is not an error");
    assert!(timed_out.height < 9_999);

    let address = c.get_new_address(None).await.expect("getnewaddress");
    assert!(address.starts_with("uregtest"), "{address}");
    let addr_info = c.get_address_info(&address).await.expect("getaddressinfo");
    assert!(addr_info.ismine);

    assert_eq!(c.get_balance(None).await.expect("getbalance").zatoshis(), 0);
    let balances = c.get_balances().await.expect("getbalances");
    assert_eq!(balances.mine.trusted.zatoshis(), 0);
    assert!(c
        .list_unspent(&zecd::typed::wallet::ListUnspentOptions::default())
        .await
        .expect("listunspent")
        .is_empty());
    assert!(c
        .list_transactions(None, None)
        .await
        .expect("listtransactions")
        .is_empty());
    assert_eq!(c.list_wallets().await.expect("listwallets"), ["default"]);

    // The async-operation surface: an unfunded z_sendmany launches, then fails with the
    // send's own -6 inside the status object - and the wait reports `finished: true` for it
    // (a failed operation is a successful wait).
    let opid = c
        .z_send_many(
            &address,
            &[zecd::typed::wallet::ZRecipient {
                address: address.clone(),
                amount: zecd::amount::Amount::from_zatoshis(10_000_000),
                memo: None,
            }],
            None,
            None,
        )
        .await
        .expect("z_sendmany launches");
    assert!(opid.starts_with("opid-"), "{opid}");
    let ids = c
        .z_list_operation_ids(None)
        .await
        .expect("z_listoperationids");
    assert!(ids.contains(&opid), "{ids:?}");
    let waited = c
        .z_wait_for_operation(&opid, Some(60))
        .await
        .expect("z_waitforoperation");
    assert!(
        waited.finished,
        "the unfunded send must finish (by failing)"
    );
    assert_eq!(waited.status, zecd::typed::wallet::OperationState::Failed);
    assert_eq!(
        waited.error.as_ref().map(|e| e.code),
        Some(-6),
        "{:?}",
        waited.error
    );

    // `Node::send`, the memo-native seam - the same unfunded send as above, but through the
    // typed-request entry point rather than `z_sendmany`'s JSON. Two things are being checked
    // live that no offline test can reach.
    //
    // First, that the seam actually rides the whole send path: the request reaches the
    // single-writer actor, a proposal is attempted against the real chain, and the failure
    // comes back as the same Bitcoin Core `-6` the RPC returns. The walletless unit test only
    // covers wallet *resolution*; nothing below the handle runs there.
    //
    // Second, and the reason this seam exists: the request pays **one address twice**, which
    // `z_sendmany` refuses outright with `-8` (zcashd parity, relaxable only by config). Paying
    // a single shielded address from several memo-carrying outputs in one transaction, for one
    // ZIP-317 fee, is the shape a memo-log consumer writes. Asserting `-6` rather than `-8`
    // proves the duplicate survived all the way to fund selection - i.e. that it failed for
    // want of money, not for being a duplicate.
    let memo_payment = |i: u8| {
        let addr = zcash_address::ZcashAddress::try_from_encoded(&address).expect("own address");
        // Via the crate's own re-export, which is the point of having it: an embedder builds
        // requests with the exact `zip321` zecd links, not a separately-pinned copy whose
        // mismatch would surface as a type error naming two identical-looking paths.
        zecd::zip321::Payment::new(
            addr,
            Some(zcash_protocol::value::Zatoshis::ZERO),
            Some(zcash_protocol::memo::MemoBytes::from_bytes(&[b'a' + i]).expect("memo")),
            None,
            None,
            vec![],
        )
        .expect("a zero-valued memo payment to a shielded address")
    };
    let duplicated = zecd::zip321::TransactionRequest::new(vec![memo_payment(0), memo_payment(1)])
        .expect("a request paying one address twice is representable");
    let err = node
        .send(None, duplicated, zecd::node::SendOptions::default())
        .await
        .expect_err("an unfunded wallet cannot pay the fee");
    assert_eq!(
        err.code,
        zecd::error::codes::RPC_WALLET_INSUFFICIENT_FUNDS,
        "duplicate shielded recipients must reach fund selection, not be rejected as \
         duplicates: {err:?}"
    );

    node.trigger_shutdown();
    node.shutdown().await;
}

/// The funded happy path for [`zecd::node::Node::send`], which the shape-walk above cannot
/// reach: it deliberately keeps an empty wallet, so every send there fails for want of funds.
/// This test completes a real send through the seam - proposal, proof, signature, broadcast -
/// and is the only place in the tree that does so through the library rather than an RPC.
///
/// Funding is ZIP-213 **shielded** coinbase mined straight to the wallet's own unified address:
/// such notes carry no maturity rule (unlike transparent coinbase's 100 blocks) and need no
/// shielding step, so the wallet simply has spendable notes once they have confirmations. The
/// address is derived *offline* from [`FUNDED_MNEMONIC`] before zebrad starts, which is what
/// lets the chain be mined into its final shape before the daemon exists - the same trick
/// `regtest_coinbase.rs` and the harness's funder use. Do not replace it with "start the node,
/// ask for an address, restart zebra to mine there": zebra's non-finalized-state backup is
/// written asynchronously, so that restart silently drops the blocks just mined.
///
/// The payment is deliberately the shape a memo-log consumer writes, and the shape
/// `z_sendmany` refuses: **two zero-valued outputs carrying memos, both to one address**. It
/// therefore proves three things at once - that a funded send completes through the seam, that
/// duplicate shielded recipients are accepted where the RPC would answer `-8`, and that the
/// wallet's own notes covered the ZIP-317 fee for outputs that move no value.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn embedded_node_send_pays_a_funded_duplicate_recipient_batch() {
    let _serial = SERIAL.lock().await;
    let Some(zebrad_bin) =
        zebrad_bin_or_skip("embedded_node_send_pays_a_funded_duplicate_recipient_batch")
    else {
        return;
    };

    let datadir = tempfile::tempdir().expect("zecd datadir");
    let phrase = || {
        <bip0039::Mnemonic<bip0039::English>>::from_phrase(FUNDED_MNEMONIC)
            .expect("the checked-in regtest phrase is valid BIP-39")
    };

    // 1. The wallet's unified address, derived offline - no chain, no wallet database, nothing
    //    on disk. This is `zecd derive-address`'s reason to exist: `init_wallet` needs a live
    //    upstream (it anchors the birthday on a tree state), so without offline derivation
    //    there would be no address to point zebra at before the wallet exists.
    let derive_config =
        zecd::config::AppConfig::resolve_overrides(&zecd::config::ConfigOverrides {
            datadir: Some(datadir.path().to_path_buf()),
            regtest: true,
            ..Default::default()
        })
        .expect("config resolves for offline derivation");
    let derived = zecd::derive_address::derive(
        &derive_config,
        zecd::derive_address::DeriveOptions {
            wallet: None,
            key: zecd::derive_address::KeyInput::Mnemonic(phrase()),
            address_type: Some("orchard"),
            index: 0,
            count: 1,
        },
    )
    .expect("derive the wallet's UA offline");
    let own_ua = derived.addresses[0].1.clone();
    assert!(own_ua.starts_with("uregtest"), "{own_ua}");

    // 2. zebra mining shielded coinbase to it from genesis. Needs zebra >= 6.0.0 (5.0.0 accepts
    //    the config but its Orchard coinbase proof fails its own validation); CI pins well past
    //    that, so a failure here is a real problem rather than an old binary, and is not
    //    skipped away.
    let (_zebrad, _zebra_dir, rpc_port) = start_mineable_zebrad(&zebrad_bin, &own_ua).await;
    // Coinbase blocks, then a confirmations tail: these are *external* receives, so the
    // ZIP-315 untrusted policy holds them unspendable for 10 confirmations. The tail is what
    // makes them spendable - no coinbase maturity rule is in play.
    mine(rpc_port, 6);
    mine(rpc_port, 15);

    // 3. The wallet restored from the phrase its address came from, birthday at genesis so the
    //    coinbase blocks are all in range.
    let config = zecd::config::AppConfig::resolve_overrides(&zecd::config::ConfigOverrides {
        datadir: Some(datadir.path().to_path_buf()),
        regtest: true,
        server: Some(format!("zebra://127.0.0.1:{rpc_port}")),
        ..Default::default()
    })
    .expect("config resolves");
    zecd::init::init_wallet(
        &config,
        zecd::init::InitOptions {
            wallet: "default".into(),
            key: zecd::init::InitKey::Restore(zecd::init::MnemonicInput::Phrase(phrase())),
            encryption: zecd::init::EncryptionInput::AgeIdentity,
            birthday: Some(1),
        },
    )
    .await
    .expect("init_wallet restores the funded wallet");

    let node = zecd::node::NodeBuilder::new(config)
        .start()
        .await
        .expect("node starts");
    let c = node.wallet(None);

    // 4. Wait for the scan *and* the enhancement drain, so the notes are not merely scanned but
    //    fully readable - the barrier this crate added for exactly this question.
    let synced = c.wait_for_sync(Some(180_000)).await.expect("waitforsync");
    assert!(synced.synced, "wallet never caught up: {synced:?}");

    let spendable = c.get_balance(None).await.expect("getbalance").zatoshis();
    assert!(
        spendable > 0,
        "shielded coinbase must be spendable after its confirmations tail; balance {spendable}"
    );

    // 5. The send: two zero-valued memo outputs to one address, through `Node::send`.
    let memo_payment = |text: &str| {
        let addr = zcash_address::ZcashAddress::try_from_encoded(&own_ua).expect("own UA");
        zecd::zip321::Payment::new(
            addr,
            Some(zcash_protocol::value::Zatoshis::ZERO),
            Some(zcash_protocol::memo::MemoBytes::from_bytes(text.as_bytes()).expect("memo")),
            None,
            None,
            vec![],
        )
        .expect("a zero-valued memo payment to a shielded address")
    };
    let request = zecd::zip321::TransactionRequest::new(vec![
        memo_payment("embedded-send-first"),
        memo_payment("embedded-send-second"),
    ])
    .expect("a request paying one address twice is representable");

    let txid = node
        .send(None, request, zecd::node::SendOptions::default())
        .await
        .expect("the funded batch send completes");

    // 6. The transaction is the wallet's own: it knows the txid, and both memos came back. The
    //    memo assertion is what proves the duplicate outputs were really both built, rather
    //    than one silently collapsing into the other.
    let tx = c
        .get_transaction(&txid.to_string())
        .await
        .expect("gettransaction on the just-sent txid");
    assert_eq!(tx.txid, txid.to_string());

    c.wait_for_sync(Some(180_000)).await.expect("waitforsync");
    let entries = c
        .z_list_transactions(Some(100), None, None, None)
        .await
        .expect("z_listtransactions");
    let memos: Vec<&str> = entries
        .iter()
        .filter(|e| e.txid == txid.to_string())
        .filter_map(|e| e.memo_str.as_deref())
        .collect();
    for expected in ["embedded-send-first", "embedded-send-second"] {
        assert!(
            memos
                .iter()
                .any(|m| m.trim_end_matches(char::from(0)) == expected),
            "both memos of the duplicate-recipient batch must survive; got {memos:?}"
        );
    }
}
