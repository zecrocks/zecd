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
    assert!(stdout.contains("init"), "help should list the init subcommand");
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
            c.args(["--datadir", dir.path().to_str().unwrap(), "--network", "bogus"]);
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
    std::fs::write(
        dir.path().join("zecd.toml"),
        "[rpc]\nbogus_field = 1\n",
    )
    .unwrap();
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

/// Full `zecd init` flow against the public testnet lightwalletd, then a re-init refusal.
/// Network: follows the repo convention for live tests (`--include-ignored`).
#[test]
#[ignore = "hits the public testnet lightwalletd"]
fn init_creates_wallet_and_refuses_reinit() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().to_str().unwrap().to_owned();

    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["--datadir", &datadir, "--network", "test", "init"]);
            c
        },
        Duration::from_secs(120),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    // The mnemonic is the last line on stdout (tracing also logs there): 24 words.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mnemonic = stdout.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
    assert_eq!(
        mnemonic.split_whitespace().count(),
        24,
        "last stdout line should be the 24-word mnemonic, got: {mnemonic:?}"
    );

    // On-disk layout: age identity at the datadir root, keys.toml in the wallet dir.
    let identity = dir.path().join("identity.txt");
    assert!(identity.exists());
    assert!(dir.path().join("default").join("keys.toml").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&identity).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity file must be private");
    }

    // A second init must refuse rather than overwrite the wallet.
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["--datadir", &datadir, "--network", "test", "init"]);
            c
        },
        Duration::from_secs(120),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("already initialized"),
        "stderr: {}",
        stderr_of(&out)
    );
}
