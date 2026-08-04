//! Black-box CLI acceptance tests: run the compiled `zecd` binary as a subprocess and
//! assert exit codes and output, modeled on zallet's `tests/acceptance.rs`.
//!
//! Everything here is offline: no test contacts a chain upstream or a running daemon.

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

// ---------------------------------------------------------------------------
// rescan
// ---------------------------------------------------------------------------

/// `rescan` deletes the wallet database, so like `init` it must take the datadir lock and
/// refuse while a daemon (or another writer) owns the directory - the guard that keeps the
/// database from being wiped out from under a live wallet.
#[test]
fn rescan_refuses_when_datadir_is_already_locked() {
    let dir = tempfile::tempdir().unwrap();
    let _held = zecd::lock::lock_datadir(dir.path()).expect("acquire the datadir lock");

    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                "rescan",
                "--yes",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "rescan against a locked datadir should refuse; stderr: {}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("already running"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// An uninitialized wallet has no `keys.toml` - the only record the rebuild would run from -
/// so `rescan` refuses rather than deleting whatever is there.
#[test]
fn rescan_refuses_an_uninitialized_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                "rescan",
                "--yes",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    let stderr = stderr_of(&out);
    assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("not initialized"), "stderr: {stderr}");
}

// ---------------------------------------------------------------------------
// example-config
// ---------------------------------------------------------------------------

/// The default mode: emit the annotated config on stdout, byte-for-byte, with nothing else
/// mixed in - so `zecd example-config > zecd.toml` is a usable starting config.
#[test]
fn example_config_prints_the_annotated_config_to_stdout() {
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.arg("example-config");
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let stdout = String::from_utf8(out.stdout).expect("utf-8 config");
    assert_eq!(
        stdout,
        zecd::example_config::EXAMPLE_CONFIG,
        "stdout must be exactly the shipped example config"
    );
    assert!(stdout.contains("[backend]") && stdout.contains("# Network:"));
}

/// The command exists to bootstrap a config, so it must not require one - nor a datadir, a
/// wallet, or a reachable chain backend. This is the regression guard for dispatching it
/// before `AppConfig::resolve`: a config that makes `resolve` *fail* must still not stop it.
#[test]
fn example_config_works_without_a_usable_config() {
    // No datadir at all.
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.arg("example-config");
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    // A datadir whose zecd.toml would be rejected by `resolve` (deny_unknown_fields).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("zecd.toml"), "[rpc]\nbogus_field = 1\n").unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["--datadir", dir.path().to_str().unwrap(), "example-config"]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(
        out.status.success(),
        "a broken config must not block generating a good one; stderr: {}",
        stderr_of(&out)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        zecd::example_config::EXAMPLE_CONFIG
    );
}

/// `-o` writes the file; a second run refuses rather than discarding a live config, and
/// `--force` is the documented way through.
#[test]
fn example_config_output_file_refuses_to_clobber_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zecd.toml");
    let path_str = path.to_str().unwrap().to_owned();

    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["example-config", "-o", &path_str]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        zecd::example_config::EXAMPLE_CONFIG
    );
    assert!(
        out.stdout.is_empty(),
        "with -o, stdout stays empty (the confirmation goes to stderr)"
    );

    // Edit it, then prove a re-run leaves the edit alone.
    std::fs::write(&path, "network = \"main\"\n").unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["example-config", "-o", &path_str]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("--force"),
        "stderr: {}",
        stderr_of(&out)
    );
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "network = \"main\"\n",
        "the existing config must survive"
    );

    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["example-config", "-o", &path_str, "--force"]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        zecd::example_config::EXAMPLE_CONFIG
    );
}

#[test]
fn help_lists_example_config_subcommand() {
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
        stdout.contains("example-config"),
        "help should list example-config: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// config check
// ---------------------------------------------------------------------------

fn config_check(conf: &std::path::Path, extra: &[&str]) -> Output {
    run_with_timeout(
        {
            let mut c = zecd();
            c.args(["config", "check", "--conf", conf.to_str().unwrap()]);
            c.args(extra);
            c
        },
        Duration::from_secs(10),
    )
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The happy path: a config this build accepts exits 0 and reports the settings it resolves
/// to - including the ones the file never mentions, which is what makes the command useful
/// across an upgrade or a rollback (every unset key takes the *binary's* default).
#[test]
fn config_check_accepts_a_valid_config_and_prints_the_effective_settings() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("zecd.toml");
    std::fs::write(
        &conf,
        format!(
            "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
            dir.path()
        ),
    )
    .unwrap();

    let out = config_check(&conf, &[]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(stdout.contains("OK:"), "{stdout}");
    // Resolved from the file...
    assert!(
        stdout.contains("network") && stdout.contains("test"),
        "{stdout}"
    );
    // ...and defaulted by this binary.
    assert!(stdout.contains("AllowRevealedRecipients"), "{stdout}");
    assert!(stdout.contains("zebra-rpc 127.0.0.1:18234"), "{stdout}");
}

/// The reason the command exists: an unknown key is rejected by `resolve`, and `config check`
/// has to report that rather than inherit it (it runs *before* `resolve` in `main`, like
/// `example-config`). The message must name the offending key, not just fail.
#[test]
fn config_check_rejects_an_unknown_key_and_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("zecd.toml");
    std::fs::write(&conf, "[rpc]\nbogus_field = 1\n").unwrap();

    let out = config_check(&conf, &[]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(stdout.contains("bogus_field"), "{stdout}");
    assert!(
        stdout.contains("error:"),
        "the report classifies the finding: {stdout}"
    );
}

/// Checking a file that isn't there is a typo'd path, not a request to validate the built-in
/// defaults - so it fails, and says which path it looked at.
#[test]
fn config_check_refuses_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("does-not-exist.toml");

    let out = config_check(&conf, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("no config file at"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// `--strict` turns warnings into a non-zero exit (a CI gate on a deployment repository),
/// while the same config passes without it.
#[test]
fn config_check_strict_fails_on_warnings_alone() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("zecd.toml");
    // No wallet is initialized in this datadir, which is a warning and nothing more.
    std::fs::write(
        &conf,
        format!(
            "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
            dir.path()
        ),
    )
    .unwrap();

    assert!(config_check(&conf, &[]).status.success());
    let out = config_check(&conf, &["--strict"]);
    assert_eq!(out.status.code(), Some(1), "stdout: {}", stdout_of(&out));
    assert!(
        stderr_of(&out).contains("--strict"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// The check must leave the datadir exactly as it found it. The cookie file is the one thing
/// that would otherwise be written - `Authenticator::from_config` mints one as a side effect -
/// and doing so against a live deployment would invalidate the credential its daemon handed out.
#[test]
fn config_check_writes_nothing_to_the_datadir() {
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().join("data");
    std::fs::create_dir(&datadir).unwrap();
    let conf = dir.path().join("zecd.toml");
    // No user/password, so this config authenticates by cookie.
    std::fs::write(
        &conf,
        format!("network = \"test\"\ndatadir = {datadir:?}\n"),
    )
    .unwrap();

    let out = config_check(&conf, &[]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    let entries: Vec<_> = std::fs::read_dir(&datadir).unwrap().collect();
    assert!(
        entries.is_empty(),
        "config check must not create files (found {} entries, e.g. a .cookie or .lock)",
        entries.len()
    );
}

/// `config check` is read-only, so - unlike `init`/`rescan` and like `export-ufvk` - it must
/// stay usable while a daemon holds the datadir lock. Checking the config of a running
/// deployment is the main thing an operator does before an upgrade.
#[test]
fn config_check_is_not_blocked_by_the_datadir_lock() {
    let dir = tempfile::tempdir().unwrap();
    let _held = zecd::lock::lock_datadir(dir.path()).expect("acquire the datadir lock");
    let conf = dir.path().join("zecd.toml");
    std::fs::write(
        &conf,
        format!(
            "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
            dir.path()
        ),
    )
    .unwrap();

    let out = config_check(&conf, &[]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
}

/// The global flags are accepted on both sides of the subcommand, and mean the same thing
/// either way - `zecd config check --conf FILE` is the spelling this command is reached for.
#[test]
fn config_check_accepts_global_flags_after_the_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let conf = dir.path().join("zecd.toml");
    std::fs::write(&conf, "network = \"test\"\n").unwrap();
    let conf_str = conf.to_str().unwrap().to_owned();

    // `--network main` after the subcommand must override the file's `network = "test"`.
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["config", "check", "--conf", &conf_str, "--network", "main"]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    assert!(stdout_of(&out).contains("main"), "{}", stdout_of(&out));

    // ...and before it, the historical position, identically.
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args(["--conf", &conf_str, "--network", "main", "config", "check"]);
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));
    assert!(stdout_of(&out).contains("main"), "{}", stdout_of(&out));
}

/// The committed testnet development mnemonic (valueless TAZ only), used here as
/// a fixed key source so the derivations below are reproducible.
const TEST_MNEMONIC: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
    midnight culture idea mountain fame park social drip bid doctor scatter glance defy moment \
    stage";

/// A second valid BIP-39 phrase (the canonical all-`abandon` test vector), for the
/// wrong-wallet case: it derives a real but different account.
const OTHER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon art";

/// Run `derive-address` with the mnemonic supplied out of band (`ZECD_MNEMONIC`), returning the
/// finished output. The datadir is a fresh temp dir that stays empty: the point of the command is
/// that it needs neither a wallet nor a chain.
fn derive_from_mnemonic(datadir: &std::path::Path, extra: &[&str]) -> Output {
    run_with_timeout(
        {
            let mut c = zecd();
            c.env("ZECD_MNEMONIC", TEST_MNEMONIC)
                .args([
                    "--datadir",
                    datadir.to_str().unwrap(),
                    "--testnet",
                    "derive-address",
                    "--mnemonic",
                ])
                .args(extra);
            c
        },
        Duration::from_secs(20),
    )
}

fn stdout_lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The core promise: an address from a mnemonic with no chain, no wallet database, and no
/// daemon - the datadir is left completely empty - and stdout carries nothing but the address,
/// so it substitutes straight into a command.
#[test]
fn derive_address_works_offline_from_a_mnemonic() {
    let dir = tempfile::tempdir().unwrap();
    let out = derive_from_mnemonic(dir.path(), &[]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    let lines = stdout_lines(&out);
    assert_eq!(
        lines.len(),
        1,
        "stdout should be exactly the address: {lines:?}"
    );
    assert!(
        lines[0].starts_with("utest1"),
        "expected a testnet unified address, got {:?}",
        lines[0]
    );

    // Nothing was written: no wallet dir, no keys.toml, no datadir lock file.
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(
        entries.is_empty(),
        "the datadir must stay untouched: {entries:?}"
    );

    // Deriving again yields the same address (unlike getnewaddress, whose shielded diversifier
    // indexes are clock-derived): determinism is what makes offline provisioning possible.
    let again = derive_from_mnemonic(dir.path(), &[]);
    assert_eq!(stdout_lines(&again), lines);
}

/// The phrase can also arrive on stdin, so a cold/air-gapped operator never puts it in a file or
/// an environment variable.
#[test]
fn derive_address_reads_the_mnemonic_from_stdin() {
    use std::io::Write as _;

    let dir = tempfile::tempdir().unwrap();
    let mut child = zecd()
        .args([
            "--datadir",
            dir.path().to_str().unwrap(),
            "--testnet",
            "derive-address",
            "--mnemonic",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning zecd");
    writeln!(child.stdin.as_mut().unwrap(), "{TEST_MNEMONIC}").unwrap();
    let out = child.wait_with_output().expect("collecting output");
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    // Same phrase, same address as the environment-variable path.
    let expected = stdout_lines(&derive_from_mnemonic(dir.path(), &[]));
    assert_eq!(stdout_lines(&out), expected);
}

/// `--count` pre-provisions a batch: one address per line, all distinct, at consecutive indices
/// starting from `--index`. `--address-type transparent` covers the exchange/miner case.
#[test]
fn derive_address_emits_a_batch_of_transparent_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let out = derive_from_mnemonic(
        dir.path(),
        &["--address-type", "transparent", "--count", "5"],
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    let lines = stdout_lines(&out);
    assert_eq!(lines.len(), 5, "{lines:?}");
    assert!(
        lines.iter().all(|l| l.starts_with("tm")),
        "expected bare testnet t-addresses: {lines:?}"
    );
    let unique: std::collections::HashSet<&String> = lines.iter().collect();
    assert_eq!(
        unique.len(),
        lines.len(),
        "addresses must be distinct: {lines:?}"
    );

    // The batch is a window over the index space: index 3 of a 5-long run from 0 is the same
    // address as the single derivation at index 3.
    let one = derive_from_mnemonic(
        dir.path(),
        &["--address-type", "transparent", "--index", "3"],
    );
    assert_eq!(stdout_lines(&one), vec![lines[3].clone()]);
}

/// `--json` reports the derivation machine-readably, including the account UFVK - the offline
/// equivalent of `export-ufvk`, which needs a wallet database.
#[test]
fn derive_address_json_reports_the_key_and_indices() {
    let dir = tempfile::tempdir().unwrap();
    let out = derive_from_mnemonic(dir.path(), &["--json", "--index", "7", "--count", "2"]);
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid JSON on stdout");
    assert_eq!(v["network"], "test");
    assert_eq!(v["source"], "mnemonic");
    assert_eq!(v["address_type"], "orchard");
    assert!(v["ufvk"].as_str().unwrap().starts_with("uviewtest1"), "{v}");
    let addrs = v["addresses"].as_array().unwrap();
    assert_eq!(addrs.len(), 2);
    assert_eq!(addrs[0]["index"], 7);
    assert_eq!(addrs[1]["index"], 8);
    assert_ne!(addrs[0]["address"], addrs[1]["address"]);
}

/// Deriving from an existing `keys.toml` uses the account viewing key pinned there, so it needs
/// no seed, no passphrase, and no wallet database - and it agrees with the mnemonic that wallet
/// was created from. Naming the wallet *and* supplying the mnemonic checks the two against each
/// other, which is how an operator confirms a `keys.toml` before trusting it with deposits.
#[test]
fn derive_address_reads_a_keys_file_and_verifies_it_against_the_mnemonic() {
    let dir = tempfile::tempdir().unwrap();
    let expected = stdout_lines(&derive_from_mnemonic(dir.path(), &[]));

    // A `keys.toml` as `init` writes one, but pinning only the viewing key (the mnemonic
    // ciphertext is irrelevant here - this path never decrypts a seed).
    let json = derive_from_mnemonic(dir.path(), &["--json"]);
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&json.stdout)).unwrap();
    let ufvk = v["ufvk"].as_str().unwrap().to_owned();
    let wallet_dir = dir.path().join("w1");
    std::fs::create_dir_all(&wallet_dir).unwrap();
    let write_keys = |ufvk: &str| {
        std::fs::write(
            wallet_dir.join("keys.toml"),
            format!("network = \"test\"\nbirthday = 1\nufvk = \"{ufvk}\"\n"),
        )
        .unwrap();
    };
    write_keys(&ufvk);

    let from_keys_file = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--testnet",
                "derive-address",
                "--wallet",
                "w1",
            ]);
            c
        },
        Duration::from_secs(20),
    );
    assert!(
        from_keys_file.status.success(),
        "stderr: {}",
        stderr_of(&from_keys_file)
    );
    assert_eq!(stdout_lines(&from_keys_file), expected);

    // Mnemonic + named wallet: the pin matches, and the match is reported.
    let verified = derive_from_mnemonic(dir.path(), &["--wallet", "w1"]);
    assert!(
        verified.status.success(),
        "stderr: {}",
        stderr_of(&verified)
    );
    assert!(
        stderr_of(&verified).contains("Verified"),
        "stderr: {}",
        stderr_of(&verified)
    );

    // A `keys.toml` pinning a *different* account is a hard failure: those addresses would not
    // be watched by the wallet that holds this seed. The foreign pin is a real key from another
    // mnemonic, so the check is a key comparison rather than a parse failure.
    let foreign = run_with_timeout(
        {
            let mut c = zecd();
            c.env("ZECD_MNEMONIC", OTHER_MNEMONIC).args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--testnet",
                "derive-address",
                "--mnemonic",
                "--json",
            ]);
            c
        },
        Duration::from_secs(20),
    );
    assert!(foreign.status.success(), "stderr: {}", stderr_of(&foreign));
    let foreign_ufvk =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&foreign.stdout))
            .unwrap()["ufvk"]
            .as_str()
            .unwrap()
            .to_owned();
    assert_ne!(foreign_ufvk, ufvk);
    write_keys(&foreign_ufvk);

    let mismatch = derive_from_mnemonic(dir.path(), &["--wallet", "w1"]);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        stderr_of(&mismatch).contains("does not match"),
        "stderr: {}",
        stderr_of(&mismatch)
    );
}

/// A wallet on another network must not be re-encoded onto the flags' network, and an
/// uninitialized wallet says how to derive without one.
#[test]
fn derive_address_refuses_a_mismatched_or_missing_keys_file() {
    let dir = tempfile::tempdir().unwrap();
    let missing = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--testnet",
                "derive-address",
            ]);
            c
        },
        Duration::from_secs(20),
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(
        stderr_of(&missing).contains("not initialized")
            && stderr_of(&missing).contains("--mnemonic"),
        "stderr: {}",
        stderr_of(&missing)
    );

    let wallet_dir = dir.path().join("default");
    std::fs::create_dir_all(&wallet_dir).unwrap();
    std::fs::write(
        wallet_dir.join("keys.toml"),
        "network = \"main\"\nbirthday = 1\nufvk = \"uview1whatever\"\n",
    )
    .unwrap();
    let wrong_network = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--testnet",
                "derive-address",
            ]);
            c
        },
        Duration::from_secs(20),
    );
    assert_eq!(wrong_network.status.code(), Some(1));
    assert!(
        stderr_of(&wrong_network).contains("is a main wallet"),
        "stderr: {}",
        stderr_of(&wrong_network)
    );
}

#[test]
fn help_lists_derive_address_subcommand() {
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
        stdout.contains("derive-address"),
        "help should list derive-address: {stdout}"
    );
}

/// `derive-address` resolves configuration like `init`/`export-ufvk` do, so a deployment's
/// `zecd.toml` sets the network and receivers its defaults follow - and an *unloadable* config
/// therefore fails the command, even when deriving from a mnemonic that needs nothing from it.
/// The documented way to derive with no deployment context is to bypass the file and name the
/// network explicitly; this pins both halves.
#[test]
fn derive_address_follows_the_config_file_and_can_bypass_it() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zecd.toml"),
        "this is not = valid toml [[[\n",
    )
    .unwrap();

    let blocked = derive_from_mnemonic(dir.path(), &[]);
    assert_eq!(blocked.status.code(), Some(1));
    assert!(
        stderr_of(&blocked).contains("parsing config"),
        "stderr: {}",
        stderr_of(&blocked)
    );

    let bypassed = run_with_timeout(
        {
            let mut c = zecd();
            c.env("ZECD_MNEMONIC", TEST_MNEMONIC).args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--conf",
                "/dev/null",
                "--testnet",
                "derive-address",
                "--mnemonic",
            ]);
            c
        },
        Duration::from_secs(20),
    );
    assert!(
        bypassed.status.success(),
        "stderr: {}",
        stderr_of(&bypassed)
    );
    assert!(
        stdout_lines(&bypassed)[0].starts_with("utest1"),
        "stdout: {:?}",
        stdout_lines(&bypassed)
    );

    // A loadable config *is* honoured: its network selects the encoding when no flag is given.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("zecd.toml"), "network = \"main\"\n").unwrap();
    let from_config = run_with_timeout(
        {
            let mut c = zecd();
            c.env("ZECD_MNEMONIC", TEST_MNEMONIC).args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "derive-address",
                "--mnemonic",
            ]);
            c
        },
        Duration::from_secs(20),
    );
    assert!(
        from_config.status.success(),
        "stderr: {}",
        stderr_of(&from_config)
    );
    assert!(
        stdout_lines(&from_config)[0].starts_with("u1"),
        "the config's network must select the encoding: {:?}",
        stdout_lines(&from_config)
    );
}
