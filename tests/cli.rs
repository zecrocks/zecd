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
            c.args([
                "--datadir",
                &datadir,
                "--network",
                "test",
                "--server",
                "zecrocks",
                "init",
            ]);
            c
        },
        Duration::from_secs(120),
    );
    assert!(out.status.success(), "stderr: {}", stderr_of(&out));

    // The mnemonic is the last line on stdout (tracing also logs there): 24 words.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mnemonic = stdout
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
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
            c.args([
                "--datadir",
                &datadir,
                "--network",
                "test",
                "--server",
                "zecrocks",
                "init",
            ]);
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

// --- tparty binary (same CLI surface under its own name/defaults) ---

fn tparty() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tparty"))
}

#[test]
fn tparty_version_prints_its_own_name() {
    let out = run_with_timeout(
        {
            let mut c = tparty();
            c.arg("--version");
            c
        },
        Duration::from_secs(10),
    );
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut words = stdout.split_whitespace();
    assert_eq!(words.next(), Some("tparty"), "got: {stdout}");
}

/// An invalid `[tparty] pool` must fail at startup (before any wallet/network I/O), and the
/// sapling variant gets the dedicated not-yet message.
#[test]
fn tparty_invalid_pool_fails_startup() {
    for (pool, expect) in [
        ("sapling", "not supported yet"),
        ("sprout", "invalid [tparty] pool"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("tparty.toml");
        std::fs::write(
            &conf,
            format!("network = \"regtest\"\n[tparty]\npool = \"{pool}\"\n"),
        )
        .unwrap();
        let out = run_with_timeout(
            {
                let mut c = tparty();
                c.args(["--conf", conf.to_str().unwrap()]);
                c
            },
            Duration::from_secs(10),
        );
        assert_eq!(out.status.code(), Some(1), "pool {pool}");
        assert!(
            stderr_of(&out).contains(expect),
            "pool {pool}: stderr: {}",
            stderr_of(&out)
        );
    }
}

/// Like zecd, tparty refuses to start on mainnet with the example placeholder password -
/// auto-shielding spend authority must never run behind a known credential.
#[test]
fn tparty_mainnet_placeholder_password_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = tparty();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--network",
                "main",
                "--rpcuser",
                "zec",
                "--rpcpassword",
                "CHANGE-ME",
            ]);
            c
        },
        Duration::from_secs(15),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("CHANGE-ME"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// End-to-end keystore migration: `zecd rewrap` re-wraps an identity-model wallet onto a
/// (fake, in-process) AWS KMS keystore, and the result unlocks via the keystore. Offline:
/// rewrap touches only keys.toml and the KMS endpoint - no chain access.
#[cfg(feature = "keystore")]
#[tokio::test(flavor = "multi_thread")]
async fn rewrap_migrates_identity_wallet_onto_kms_keystore() {
    use age::secrecy::ExposeSecret as _;

    // The committed testnet test mnemonic (valueless), as a deterministic fixture.
    const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";
    const KEY_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/cli-rewrap-test";

    zecd::keystore::fake::set_fake_credentials();
    let endpoint = zecd::keystore::fake::spawn_aws(KEY_ARN).await;

    // Fabricate an identity-model wallet (what `init` would produce, minus the chain I/O
    // and the wallet DB - rewrap reads neither).
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path();
    let identity = age::x25519::Identity::generate();
    std::fs::write(
        datadir.join("identity.txt"),
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .unwrap();
    let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(PHRASE).unwrap();
    let recipient = identity.to_public();
    zecd::wallet::store::WalletStore::init_with_mnemonic(
        &datadir.join("default"),
        std::iter::once(&recipient as &dyn age::Recipient),
        &mnemonic,
        zcash_protocol::consensus::BlockHeight::from_u32(1),
        zecd::network::ZNetwork::Test,
    )
    .unwrap();
    std::fs::write(
        datadir.join("zecd.toml"),
        format!(
            "network = \"test\"\n[keystore]\nprovider = \"aws-kms\"\nkey = \"{KEY_ARN}\"\nendpoint = \"{endpoint}\"\n"
        ),
    )
    .unwrap();

    let out = tokio::task::spawn_blocking({
        let datadir = datadir.to_path_buf();
        move || {
            run_with_timeout(
                {
                    let mut c = zecd();
                    c.args(["--datadir", datadir.to_str().unwrap(), "rewrap"]);
                    // The compiled binary resolves AWS credentials from its own env.
                    c.env("AWS_ACCESS_KEY_ID", "test")
                        .env("AWS_SECRET_ACCESS_KEY", "test")
                        .env("AWS_EC2_METADATA_DISABLED", "true");
                    c
                },
                Duration::from_secs(30),
            )
        }
    })
    .await
    .unwrap();
    assert!(out.status.success(), "rewrap failed: {}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("aws-kms"),
        "stderr: {}",
        stderr_of(&out)
    );

    // keys.toml now carries the KMS marker and metadata...
    let keys_toml = std::fs::read_to_string(datadir.join("default/keys.toml")).unwrap();
    assert!(keys_toml.contains("encryption = \"kms\""), "{keys_toml}");
    assert!(keys_toml.contains(KEY_ARN), "{keys_toml}");

    // ...and the wallet unlocks through the keystore (the daemon's startup path).
    let st = zecd::wallet::store::WalletStore::read(&datadir.join("default")).unwrap();
    assert!(
        !st.is_encrypted(),
        "KMS wallets are Bitcoin-Core-unencrypted"
    );
    let back = zecd::wallet::keys::decrypt_mnemonic_with_keystore(&st, Some(&endpoint))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(&back).as_slice(),
        PHRASE.as_bytes()
    );
}

/// `init --keystore` must fail fast (before any chain I/O) when no [keystore] is configured.
#[test]
fn init_keystore_without_config_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_with_timeout(
        {
            let mut c = zecd();
            c.args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--testnet",
                "init",
                "--keystore",
            ]);
            c
        },
        Duration::from_secs(10),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr_of(&out).contains("no cloud keystore configured"),
        "stderr: {}",
        stderr_of(&out)
    );
}

/// A half-configured [keystore] (provider without key) is a startup error, not a surprise
/// at the first unlock.
#[test]
fn half_configured_keystore_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zecd.toml"),
        "network = \"test\"\n[keystore]\nprovider = \"aws-kms\"\n",
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
        stderr_of(&out).contains("[keystore]"),
        "stderr: {}",
        stderr_of(&out)
    );
}
