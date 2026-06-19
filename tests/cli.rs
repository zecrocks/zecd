//! Black-box CLI acceptance tests: run the compiled `zecd` binary as a subprocess and
//! assert exit codes and output, modeled on zallet's `tests/acceptance.rs`.
//!
//! Everything here is offline except the `#[ignore]`d init test, which follows the
//! repo convention for tests that hit the public testnet lightwalletd
//! (`cargo test -- --include-ignored`).

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn zecd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_zecd"))
}

/// Run to completion, killing the child if it is still alive after `timeout` - a
/// startup-failure path that regresses into a running daemon should fail the test,
/// not hang CI.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Output {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .expect("spawning zecd");
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("polling zecd") {
            Some(_) => return child.wait_with_output().expect("collecting output"),
            None if Instant::now() >= deadline => {
                child.kill().ok();
                child.wait().ok();
                panic!("zecd did not exit within {timeout:?}; expected a fast failure");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn version_prints_name_and_semver() {
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.arg("--version");
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut words = stdout.split_whitespace();
    assert_eq!(words.next(), Some("zecd"));
    let version = words.next().expect("version after name");
    assert!(
        version.split('.').count() >= 3
            && version.chars().next().is_some_and(|c| c.is_ascii_digit()),
        "expected semver, got {version:?}"
    );
}

#[test]
fn help_lists_init_subcommand() {
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.arg("--help");
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("init"),
        "help should list the init subcommand"
    );
}

#[test]
fn unknown_flag_is_a_usage_error() {
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.arg("--definitely-not-a-flag");
            c
        },
        Duration::from_secs(10),
    );
    // clap's conventional usage-error exit code, same as bitcoind's arg parsing.
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_of(&out));
}

#[test]
fn invalid_network_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "bogus",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("unsupported network"),
        "stderr: {}",
        stderr_of(&out)
    );
}

#[test]
fn unknown_config_field_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("zecd.toml"), "[rpc]\nbogus_field = 1\n").unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["--datadir", dir.path().to_str().unwrap()]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("parsing config"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// On mainnet the RPC password is spend authority, so the daemon must refuse to start while it is
/// still the shipped placeholder - in any case, since the deploy templates use `CHANGE-ME` and the
/// example config uses lowercase `change-me`.
#[test]
fn mainnet_placeholder_password_refuses_to_start() {
    for placeholder in ["CHANGE-ME", "change-me", " Change-Me "] {
        let dir = tempfile::tempdir().unwrap();
        let out = run_with_timeout(
            {
                let mut c = zecd();
                c.args([
                    "--datadir",
                    dir.path().to_str().unwrap(),
                    "--network",
                    "main",
                    "--rpcuser",
                    "u",
                    "--rpcpassword",
                    placeholder,
                ]);
                c
            },
            Duration::from_secs(10),
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "placeholder {placeholder:?} should refuse to start; stderr: {}",
            stderr_of(&out)
        );
        assert!(
            stderr_of(&out).contains("CHANGE-ME"),
            "placeholder {placeholder:?} stderr: {}",
            stderr_of(&out)
        );
    }
}

#[test]
fn malformed_rpcauth_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
                "--rpcauth",
                "no-colon-or-dollar",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("invalid rpcauth entry"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// `zecd rpcauth <user> [password]` generates a salted `[rpc] auth` line with no external
/// `rpcauth.py`. With an explicit password it emits just the line; without one it also prints
/// the minted password. The emitted line must be a well-formed `<user>:<salt>$<64 hex>` entry.
#[test]
fn rpcauth_generates_credential_line() {
    fn auth_line(stdout: &str) -> &str {
        stdout
            .lines()
            .find_map(|l| l.trim().strip_prefix("auth = [\""))
            .and_then(|l| l.strip_suffix("\"]"))
            .expect("an auth = [\"...\"] line")
    }

    // Explicit password: line only, no secret printed back.
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["rpcauth", "alice", "hunter2"]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let entry = auth_line(&stdout);
    let (user, pwhash) = entry.split_once(':').expect("user:hash");
    assert_eq!(user, "alice");
    let (salt, hash) = pwhash.split_once('$').expect("salt$hash");
    assert!(!salt.is_empty() && salt.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        !stdout.contains("password"),
        "explicit password must not print a generated secret: {stdout}"
    );

    // No password: a secret is generated and printed alongside the line.
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["rpcauth", "bob"]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let entry = auth_line(&stdout);
    assert!(entry.starts_with("bob:"));
    assert!(
        stdout.to_lowercase().contains("password"),
        "a generated password must be surfaced: {stdout}"
    );
}

/// A typo'd method in the `[rpc] allowed_methods` safelist must fail at startup, not silently
/// disable a method the operator believed they had enabled.
#[test]
fn unknown_allowed_method_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zecd.toml"),
        "[rpc]\nallowed_methods = [\"getbalance\", \"not_a_real_method\"]\n",
    )
    .unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("not_a_real_method"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// A default receiver that names a pool the wallet doesn't enable is a startup error, caught at
/// config parse before any network/wallet I/O.
#[test]
fn default_receivers_not_subset_of_pools_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zecd.toml"),
        "[pools]\nenabled = [\"orchard\"]\ndefault_receivers = [\"sapling\"]\n",
    )
    .unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("subset") && stderr_of(&out).contains("sapling"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// An unknown pool name in `[pools]` is rejected at startup.
#[test]
fn unknown_pool_name_fails_startup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zecd.toml"),
        "[pools]\nenabled = [\"ironwood\"]\n",
    )
    .unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "test",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("ironwood"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// A malformed `--ufvk` fails fast and offline: the key is parsed before any upstream
/// connection (so no server is contacted for a key that can never import).
#[test]
fn init_with_invalid_ufvk_fails_before_any_network_io() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                // A dead local endpoint: if init wrongly dialed before parsing the UFVK, the
                // connect error (not the parse error) would surface.
                "--server",
                "127.0.0.1:1",
                "init",
                "--ufvk",
                "not-a-viewing-key",
            ]);
            c
        },
        Duration::from_secs(30),
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("invalid unified full viewing key"),
        "stderr: {}",
        stderr_of(&out)
    );
    // No wallet was created for the bad key.
    assert!(!dir.path().join("default").join("keys.toml").exists());
}

/// `--ufvk` is a watch-only init: combining it with `--restore` (a mnemonic) or `--encrypt`
/// (a passphrase over the mnemonic) is contradictory, refused at the clap level.
#[test]
fn init_ufvk_conflicts_with_restore_and_encrypt() {
    for other in ["--restore", "--encrypt"] {
        let dir = tempfile::tempdir().unwrap();
        let out = run_with_timeout(
            {
                let mut c = zecd();
                c.args([
                    "--datadir",
                    dir.path().to_str().unwrap(),
                    "--regtest",
                    "init",
                    "--ufvk",
                    "uviewregtest1fake",
                    other,
                ]);
                c
            },
            Duration::from_secs(10),
        );
        // clap's conventional usage-error exit code.
        assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_of(&out));
        assert!(
            stderr_of(&out).contains("cannot be used with"),
            "stderr: {}",
            stderr_of(&out)
        );
    }
}

/// `export-ufvk` refuses cleanly when the wallet does not exist (nothing to export).
#[test]
fn export_ufvk_requires_an_initialized_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                "export-ufvk",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("not initialized"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// Single-instance guard: a datadir-writing command (`init`) refuses to start when the datadir
/// is already locked by another zecd. The test process holds the lock (standing in for a running
/// daemon); the spawned `zecd init` must bail fast with the "already running" message - the lock
/// is taken before any network or filesystem work, so this is offline.
#[test]
fn init_refuses_when_datadir_is_already_locked() {
    let dir = tempfile::tempdir().unwrap();
    let _held = zecd::lock::lock_datadir(dir.path()).expect("acquire the datadir lock");

    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                "init",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "init against a locked datadir should refuse; stderr: {}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("already running"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// The read-only `export-ufvk` is deliberately exempt from the datadir lock (it only reads the
/// wallet DB, so it is safe to run alongside a live daemon). Even with the lock held, it must get
/// past the guard and fail on its own "not initialized" check - never on "already running".
#[test]
fn export_ufvk_is_not_blocked_by_the_datadir_lock() {
    let dir = tempfile::tempdir().unwrap();
    let _held = zecd::lock::lock_datadir(dir.path()).expect("acquire the datadir lock");

    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                "export-ufvk",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        stderr.contains("not initialized"),
        "export-ufvk should reach its own check, not the lock guard; stderr: {stderr}"
    );
    assert!(
        !stderr.contains("already running"),
        "export-ufvk must not be blocked by the datadir lock; stderr: {stderr}"
    );
}
