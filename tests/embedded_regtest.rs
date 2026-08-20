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

/// The regtest chain shape zecd's `network::regtest()` expects (the harness's template minus
/// the NU6.3 activation): NU5/NU6 from genesis, NU6.1/NU6.2 at height 4 with the ZIP-271
/// lockbox disbursement their activation block requires.
fn zebrad_toml(net_port: u16, rpc_port: u16, cache_dir: &str) -> String {
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
miner_address = "{MINER_ADDRESS}"

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

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn embedded_node_serves_typed_calls_end_to_end() {
    if std::env::var("ZECD_EMBEDDED_REGTEST").as_deref() != Ok("1") {
        eprintln!("skipping: set ZECD_EMBEDDED_REGTEST=1 (and ZEBRAD_BIN) to run");
        return;
    }
    let Some(zebrad_bin) = std::env::var("ZEBRAD_BIN")
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
    else {
        eprintln!("skipping: ZEBRAD_BIN is unset or not a file");
        return;
    };

    // Bring up a throwaway zebrad regtest node.
    let zebra_dir = tempfile::tempdir().expect("zebrad tempdir");
    let rpc_port = free_port();
    let net_port = free_port();
    let config_path = zebra_dir.path().join("zebrad.toml");
    let cache_dir = zebra_dir.path().join("state");
    std::fs::write(
        &config_path,
        zebrad_toml(net_port, rpc_port, &cache_dir.to_string_lossy()),
    )
    .expect("write zebrad.toml");
    let _zebrad = KillOnDrop(
        Command::new(&zebrad_bin)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zebrad"),
    );
    // Poll `getblocktemplate`, NOT `getblockchaininfo`: the latter answers as soon as the RPC
    // server binds, while `generate` additionally needs zebra to consider its state ready and
    // refuses with "Zebra's state is empty, wait until it syncs to the chain tip" until then.
    // That gap is real - it failed in CI this way - and it widens under the load of the harness
    // binaries running alongside. The template endpoint is the precondition for mining, so it is
    // the thing to wait on (the regtest harness's own `wait_until_rpc_up` polls it for exactly
    // this reason).
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match zebra_rpc(rpc_port, "getblocktemplate", "[]") {
            Ok(_) => break,
            Err(e) if Instant::now() < deadline => {
                eprintln!("waiting for zebrad to become mineable: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("zebrad never became mineable: {e}"),
        }
    }
    let mined = zebra_rpc(rpc_port, "generate", "[10]").expect("mine 10 blocks");
    assert_eq!(mined.as_array().map(|a| a.len()), Some(10), "{mined}");

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

    node.trigger_shutdown();
    node.shutdown().await;
}
