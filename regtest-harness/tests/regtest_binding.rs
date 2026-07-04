//! End-to-end test of the account-to-keys binding (`wallet::binding`): `zecd init` pins the
//! account's UFVK into `keys.toml`, startup verifies the wallet database against the pin
//! (backfilling it on a pre-pin `keys.toml`), and a swapped `data.sqlite` refuses to serve,
//! both at daemon startup and at `zecd init` time.
//!
//! Skips cleanly when the node binary isn't provisioned (so plain `cargo test` and the
//! build-only CI path still validate that the harness compiles). Provide `ZEBRAD_BIN` to run
//! the full flow (see README.md). Runs in the default (non-extended) tier: it needs only one
//! zebra and two short-lived zecd instances.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::json;
use zecd_regtest_harness::{pick_port, resolve_bin, zecd_bin, Zebrad, Zecd, ZecdConfig};

/// Blocks mined before launching zecd. Regtest mining is cheap (PoW disabled).
const INITIAL_BLOCKS: u32 = 10;
/// Generous: zecd scan over a fresh regtest chain.
const SYNC_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the pinned `ufvk` value out of a wallet's `keys.toml`, if present.
fn pinned_ufvk(keys_toml: &Path) -> Option<String> {
    let text = std::fs::read_to_string(keys_toml).expect("read keys.toml");
    text.lines().find_map(|line| {
        line.strip_prefix("ufvk = \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .map(str::to_string)
    })
}

/// Rewrite `keys.toml` without its `ufvk` line, simulating a file written by a zecd from
/// before the pin existed (the upgrade path the daemon must backfill).
fn strip_pin(keys_toml: &Path) {
    let text = std::fs::read_to_string(keys_toml).expect("read keys.toml");
    let stripped: String = text
        .lines()
        .filter(|line| !line.starts_with("ufvk = "))
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(keys_toml, stripped).expect("rewrite keys.toml without the pin");
}

#[tokio::test]
async fn regtest_account_binding() {
    let Some(zebrad_bin) = resolve_bin("ZEBRAD_BIN") else {
        eprintln!(
            "SKIP regtest_account_binding: set ZEBRAD_BIN to run the live e2e (see README.md). \
             The harness still compiled and linked."
        );
        return;
    };

    let zebrad = Zebrad::start(&zebrad_bin)
        .await
        .expect("launch zebrad regtest");
    zebrad
        .generate_blocks(INITIAL_BLOCKS)
        .await
        .expect("mine initial regtest blocks");

    // ---- 1. init pins the account UFVK into keys.toml, and it matches export-ufvk ----

    let cfg = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick zecd rpc port"));
    let mut zecd = Zecd::start(&cfg).await.expect("start zecd");
    zecd.wait_until_synced(INITIAL_BLOCKS as u64, SYNC_TIMEOUT)
        .await
        .expect("zecd scans to the regtest tip");

    let keys_toml = zecd.datadir().join("default").join("keys.toml");
    let pin = pinned_ufvk(&keys_toml).expect("zecd init must pin the account UFVK");
    assert!(
        pin.starts_with("uviewregtest1"),
        "the pin is a regtest-encoded UFVK, got {pin}"
    );
    let exported = zecd.export_ufvk("default").expect("export-ufvk");
    assert_eq!(
        pin, exported,
        "the pinned UFVK is exactly the account's (export-ufvk) key"
    );

    // ---- 2. a pre-pin keys.toml starts normally and gets the pin backfilled ----

    zecd.stop_keeping_datadir().await.expect("stop zecd");
    strip_pin(&keys_toml);
    assert_eq!(pinned_ufvk(&keys_toml), None, "pin stripped for the test");
    zecd.respawn().await.expect("a legacy keys.toml must start");
    let addr = zecd
        .call("getnewaddress", json!([]))
        .await
        .expect("the upgraded wallet serves RPCs");
    assert!(addr.as_str().unwrap_or_default().starts_with("uregtest1"));
    assert_eq!(
        pinned_ufvk(&keys_toml).as_deref(),
        Some(exported.as_str()),
        "startup backfills the pin trust-on-first-use with the account's real UFVK"
    );

    // ---- 3. a swapped data.sqlite refuses to serve (fail closed) ----

    // A second, unrelated wallet supplies the foreign database (its own fresh mnemonic).
    let cfg_b = ZecdConfig::new(zebrad.rpc_port, pick_port().expect("pick second rpc port"));
    let mut foreign = Zecd::start(&cfg_b).await.expect("start the foreign zecd");
    foreign
        .stop_keeping_datadir()
        .await
        .expect("stop the foreign zecd");
    let foreign_db = foreign.datadir().join("default").join("data.sqlite");

    zecd.stop_keeping_datadir().await.expect("stop zecd again");
    let wallet_dir = zecd.datadir().join("default");
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(wallet_dir.join(format!("data.sqlite{suffix}")));
    }
    std::fs::copy(&foreign_db, wallet_dir.join("data.sqlite")).expect("swap in the foreign db");

    let stderr = zecd
        .respawn_expect_startup_failure()
        .await
        .expect("a swapped database must refuse startup");
    assert!(
        stderr.contains("keys.toml") && stderr.contains("does not"),
        "the refusal names the binding mismatch; stderr:\n{stderr}"
    );

    // ---- 4. `zecd init` refuses a database that already contains an account ----

    // The foreign wallet's datadir, with keys.toml removed: exactly the audit's scenario of a
    // pre-existing account-bearing database in a directory about to be initialized. The guard
    // runs before any interactive or network I/O, so the refusal is immediate.
    std::fs::remove_file(foreign.datadir().join("default").join("keys.toml"))
        .expect("remove the foreign wallet's keys.toml");
    let out = Command::new(zecd_bin())
        .args([
            "--datadir",
            foreign.datadir().to_str().unwrap(),
            "--regtest",
            "init",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run zecd init on the account-bearing datadir");
    assert!(
        !out.status.success(),
        "init into an account-bearing database must refuse"
    );
    let init_err = String::from_utf8_lossy(&out.stderr);
    assert!(
        init_err.contains("already contains"),
        "the init refusal names the pre-existing account; stderr:\n{init_err}"
    );
}
