//! Data-directory layout migration: moving librustzcash's files out of the wallet directory
//! root and into the per-coin, per-engine subdirectory that now holds them.
//!
//! Older zecd put a wallet's databases directly in its directory, beside `keys.toml`:
//!
//! ```text
//! <datadir>/<wallet>/{keys.toml, data.sqlite, blockmeta.sqlite, blocks/}
//! ```
//!
//! They now live one coin and one engine deeper, leaving `keys.toml` alone at the wallet root:
//!
//! ```text
//! <datadir>/<wallet>/keys.toml
//! <datadir>/<wallet>/zec/lrz/{data.sqlite, blockmeta.sqlite, blocks/}
//! ```
//!
//! The split follows what can be rebuilt from what. `keys.toml` wraps a BIP-39 seed that serves
//! every coin and that nothing on any chain can reconstruct, so it stays at the top, shared.
//! Everything below it is derived state, namespaced by the coin that owns it
//! ([`Coin::data_dir`]) and then by the library that wrote it ([`Coin::engine_dir`]) - so a
//! second coin gets a sibling directory rather than a share of one flat namespace, and
//! replacing the storage library (or migrating between two incompatible generations of it)
//! is a sibling directory and a rescan.
//!
//! [`migrate`] performs the move once, on the first start of a build that ships this layout.
//! Each artifact is **renamed** within the wallet directory, never copied: no free disk space is
//! needed, nothing is deleted, and a run interrupted part-way simply moves what is left on the
//! next start. The caller must hold the datadir lock ([`crate::lock::lock_datadir`]) - the
//! daemon migrates in [`crate::node::PreparedNode::start`], `zecd init` and `zecd rescan` in
//! their own lock scopes. Nothing here ever deletes anything; the one case it cannot resolve
//! is an error that leaves both copies on disk for the operator.
//!
//! Read-only commands take no lock and so cannot migrate. `zecd export-ufvk` reads an
//! un-migrated wallet database in place - see [`engine_dir_for_reading`]. `zecd derive-address`
//! needs no fallback at all: it reads only `keys.toml`, which this migration never moves.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use tracing::{info, warn};

use crate::coin::Coin;
use crate::config::{self, AppConfig, WalletEntry};

/// Everything librustzcash owns inside a wallet directory, relative to the directory it lives
/// in - the complete set this migration moves.
///
/// The SQLite `-wal`/`-shm` sidecars are listed explicitly and moved with their databases: a
/// `-wal` holds committed transactions that have not been checkpointed back yet, so moving a
/// database without it would silently discard the most recent writes. Nothing else in a wallet
/// directory is librustzcash's - `keys.toml` is zecd's own and stays at the root.
pub const ENGINE_ARTIFACTS: [&str; 7] = [
    "data.sqlite",
    "data.sqlite-wal",
    "data.sqlite-shm",
    "blockmeta.sqlite",
    "blockmeta.sqlite-wal",
    "blockmeta.sqlite-shm",
    "blocks",
];

/// The artifact whose presence at a wallet directory's root means that wallet predates this
/// layout. The others may legitimately be absent (a wallet that never scanned has no block
/// cache; the sidecars exist only between a write and a checkpoint).
const PRIMARY_ARTIFACT: &str = "data.sqlite";

/// One wallet's pending move: the artifacts still sitting at its root, and where they go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMove {
    /// The wallet whose directory this is.
    pub wallet: String,
    /// The wallet directory the artifacts are sitting in.
    pub from: PathBuf,
    /// The engine directory they belong in: `<from>/<coin>/<engine>`.
    pub to: PathBuf,
    /// The artifact names to move, a subset of [`ENGINE_ARTIFACTS`] in that order.
    pub artifacts: Vec<String>,
}

/// Decide which wallets have librustzcash files still at their root, and refuse the one
/// situation that cannot be resolved without an operator's judgement.
///
/// Unlike a layout change that moved wallet directories themselves, this one happens *inside*
/// each wallet directory - so a `[wallets.<name>] dir` override is migrated like any other
/// wallet. The operator's path keeps its meaning; only its contents are rearranged.
pub fn plan(config: &AppConfig) -> anyhow::Result<Vec<WalletMove>> {
    let mut moves = Vec::new();
    for (name, entry) in &config.wallets {
        let from = &entry.dir;
        let to = entry.engine_dir();
        let mut artifacts = Vec::new();
        for artifact in ENGINE_ARTIFACTS {
            if !from.join(artifact).exists() {
                continue;
            }
            // The same artifact in both places is ambiguous - which database is the real one is
            // not zecd's call. Refuse and say so, leaving both untouched. Note this compares
            // artifact by artifact, so a migration interrupted half way (some moved, some not)
            // resumes rather than tripping this.
            if to.join(artifact).exists() {
                return Err(anyhow!(
                    "wallet '{name}' has {artifact} both at {} and at {}. zecd will not choose \
                     between them: keep the one you want (the current layout is {}), move the \
                     other out of the wallet directory, and start zecd again",
                    from.join(artifact).display(),
                    to.join(artifact).display(),
                    to.display(),
                ));
            }
            artifacts.push(artifact.to_string());
        }
        if !artifacts.is_empty() {
            moves.push(WalletMove {
                wallet: name.clone(),
                from: from.clone(),
                to,
                artifacts,
            });
        }
    }
    Ok(moves)
}

/// Move any librustzcash files still at a wallet directory's root into that wallet's engine
/// directory, returning what was moved (empty on an already-migrated - or brand new - data
/// directory, which is the common case).
///
/// The caller must hold the datadir lock. Failure is fatal to startup on purpose: the data is
/// still on disk, untouched, and starting anyway would rebuild an empty wallet database beside
/// it and rescan the chain.
pub fn migrate(config: &AppConfig) -> anyhow::Result<Vec<WalletMove>> {
    let moves = plan(config)?;
    if moves.is_empty() {
        return Ok(moves);
    }
    info!(
        wallets = moves.len(),
        "moving wallet databases into their per-coin engine directories (one-time data \
         directory layout migration)"
    );
    for m in &moves {
        apply(m)?;
        info!(
            wallet = %m.wallet,
            artifacts = m.artifacts.len(),
            "moved {} -> {}",
            m.from.display(),
            m.to.display()
        );
    }
    Ok(moves)
}

/// Perform one wallet's move. Every step is a rename within the wallet directory, so each is
/// atomic and the sequence as a whole is resumable ([`plan`] simply lists whatever is left).
fn apply(m: &WalletMove) -> anyhow::Result<()> {
    std::fs::create_dir_all(&m.to).with_context(|| format!("creating {}", m.to.display()))?;
    for artifact in &m.artifacts {
        let from = m.from.join(artifact);
        let to = m.to.join(artifact);
        std::fs::rename(&from, &to).with_context(|| {
            format!(
                "moving {} to {} for wallet '{}'. The data is untouched at {}; if the two paths \
                 are on different filesystems, move it there yourself and start zecd again",
                from.display(),
                to.display(),
                m.wallet,
                from.display()
            )
        })?;
    }
    Ok(())
}

/// The directory to open this wallet's librustzcash databases from **without migrating them**:
/// normally [`WalletEntry::engine_dir`], but the wallet directory itself while the wallet is
/// still in the pre-`<coin>/<engine>/` layout.
///
/// `zecd export-ufvk` deliberately takes no datadir lock (it must run beside a live daemon), so
/// it may not move anything - but it should still read a wallet the daemon has not migrated
/// yet, rather than report it uninitialized. The fallback applies only when the engine
/// directory holds no wallet database and the wallet root does, so it can never shadow a
/// migrated wallet.
pub fn engine_dir_for_reading(entry: &WalletEntry) -> PathBuf {
    let engine = entry.engine_dir();
    if engine.join(PRIMARY_ARTIFACT).is_file() || !entry.dir.join(PRIMARY_ARTIFACT).is_file() {
        return engine;
    }
    warn!(
        "reading the wallet database from its pre-{}/{}/ location {}; the next `zecd run` (or \
         `zecd init`/`zecd rescan`) moves it to {}",
        entry.coin.data_dir(),
        entry.coin.engine_dir(),
        entry.dir.display(),
        engine.display()
    );
    entry.dir.clone()
}

/// Whether `wallet_dir` still holds a wallet database at its root, i.e. predates this layout.
/// Used by `zecd config check` to report a pending migration without performing one.
pub fn awaits_migration(wallet_dir: &Path, coin: Coin) -> bool {
    wallet_dir.join(PRIMARY_ARTIFACT).is_file()
        && !config::engine_dir(wallet_dir, coin)
            .join(PRIMARY_ARTIFACT)
            .is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigOverrides;

    /// Resolve a config against `dir` as the data directory, from an optional `zecd.toml` body.
    fn config_with(dir: &Path, toml: &str) -> AppConfig {
        let conf = dir.join("zecd.toml");
        std::fs::write(&conf, format!("network = \"test\"\n{toml}")).unwrap();
        AppConfig::resolve_overrides(&ConfigOverrides {
            conf: Some(conf),
            datadir: Some(dir.to_path_buf()),
            ..Default::default()
        })
        .expect("config resolves")
    }

    /// A wallet directory in the pre-`zec/lrz/` layout: everything at the root, including the
    /// `-wal` sidecar a live database leaves behind.
    fn make_legacy_wallet(dir: &Path) {
        std::fs::create_dir_all(dir.join("blocks")).unwrap();
        std::fs::write(dir.join("keys.toml"), "network = \"test\"\n").unwrap();
        std::fs::write(dir.join("data.sqlite"), b"db").unwrap();
        std::fs::write(dir.join("data.sqlite-wal"), b"wal").unwrap();
        std::fs::write(dir.join("blockmeta.sqlite"), b"meta").unwrap();
        std::fs::write(dir.join("blocks").join("1-aa.compact"), b"b").unwrap();
    }

    /// Assert a wallet is fully migrated: databases under `zec/lrz/`, `keys.toml` still at the
    /// root, and nothing librustzcash's left behind.
    fn assert_migrated(wallet_dir: &Path) {
        let engine = wallet_dir.join("zec").join("lrz");
        assert!(engine.join("data.sqlite").is_file(), "the wallet database");
        assert!(engine.join("data.sqlite-wal").is_file(), "its wal sidecar");
        assert!(
            engine.join("blockmeta.sqlite").is_file(),
            "the cache meta db"
        );
        assert!(
            engine.join("blocks").join("1-aa.compact").is_file(),
            "the compact-block cache"
        );
        assert!(
            wallet_dir.join("keys.toml").is_file(),
            "keys.toml stays at the wallet root"
        );
        for artifact in ENGINE_ARTIFACTS {
            assert!(
                !wallet_dir.join(artifact).exists(),
                "{artifact} was moved, not copied"
            );
        }
    }

    #[test]
    fn a_legacy_wallet_moves_into_its_engine_directory() {
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        let config = config_with(dir.path(), "");

        let moved = migrate(&config).expect("migration succeeds");
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].wallet, "default");
        assert_migrated(&dir.path().join("default"));
        assert_eq!(config.wallets["default"].engine_dir(), moved[0].to);
    }

    #[test]
    fn the_wal_sidecar_travels_with_its_database() {
        // A `-wal` holds committed-but-uncheckpointed transactions, so leaving it behind would
        // silently roll the wallet back to its last checkpoint.
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        let config = config_with(dir.path(), "");

        let moved = migrate(&config).unwrap();
        assert!(
            moved[0].artifacts.iter().any(|a| a == "data.sqlite-wal"),
            "the wal is part of the move: {:?}",
            moved[0].artifacts
        );
        assert_eq!(
            std::fs::read(dir.path().join("default/zec/lrz/data.sqlite-wal")).unwrap(),
            b"wal"
        );
    }

    #[test]
    fn migration_is_a_no_op_once_it_has_run() {
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        let config = config_with(dir.path(), "");

        assert_eq!(migrate(&config).unwrap().len(), 1);
        assert!(
            migrate(&config).unwrap().is_empty(),
            "a migrated wallet has nothing left to move"
        );
        assert_migrated(&dir.path().join("default"));
    }

    #[test]
    fn a_fresh_data_directory_has_nothing_to_migrate() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_with(dir.path(), "");
        assert!(migrate(&config).unwrap().is_empty());
        assert!(
            !dir.path().join("default").exists(),
            "migration must not create directories it has no data for"
        );
    }

    #[test]
    fn an_uninitialized_wallet_directory_is_left_alone() {
        // keys.toml but no database: a wallet mounted from a Secret onto an empty datadir, which
        // the daemon's bootstrap path rebuilds. There is nothing to move, and no engine
        // directory should be conjured for it either.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("default")).unwrap();
        std::fs::write(
            dir.path().join("default").join("keys.toml"),
            "network = \"test\"\n",
        )
        .unwrap();
        let config = config_with(dir.path(), "");

        assert!(migrate(&config).unwrap().is_empty());
        assert!(!dir.path().join("default").join("zec").exists());
    }

    #[test]
    fn every_configured_wallet_moves() {
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        make_legacy_wallet(&dir.path().join("watcher"));
        let config = config_with(dir.path(), "[wallets.watcher]\n");

        assert_eq!(migrate(&config).unwrap().len(), 2);
        assert_migrated(&dir.path().join("default"));
        assert_migrated(&dir.path().join("watcher"));
    }

    /// Unlike a layout change that relocated wallet directories, this one rearranges each
    /// wallet *inside* whatever directory the operator named - so an explicit `dir` is migrated
    /// like any other wallet rather than opted out.
    #[test]
    fn a_wallet_at_an_explicit_dir_is_migrated_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        make_legacy_wallet(&elsewhere);
        let config = config_with(
            dir.path(),
            &format!("[wallets.default]\ndir = {:?}\n", elsewhere),
        );

        assert_eq!(migrate(&config).unwrap().len(), 1);
        assert_migrated(&elsewhere);
    }

    #[test]
    fn a_keys_file_mounted_outside_the_wallet_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        let keys = dir.path().join("secret-keys.toml");
        std::fs::write(&keys, "network = \"test\"\n").unwrap();
        let config = config_with(
            dir.path(),
            &format!("[wallets.default]\nkeys_file = {:?}\n", keys),
        );

        assert_eq!(migrate(&config).unwrap().len(), 1);
        assert_migrated(&dir.path().join("default"));
        assert!(keys.is_file(), "the mounted keys file stays put");
    }

    #[test]
    fn the_same_artifact_in_both_places_is_refused_without_deleting_either() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("default");
        make_legacy_wallet(&wallet);
        std::fs::create_dir_all(wallet.join("zec").join("lrz")).unwrap();
        std::fs::write(wallet.join("zec").join("lrz").join("data.sqlite"), b"other").unwrap();
        let config = config_with(dir.path(), "");

        let err = migrate(&config).expect_err("an ambiguous database must refuse");
        let msg = format!("{err:#}");
        assert!(msg.contains("data.sqlite both at"), "{msg}");
        assert_eq!(std::fs::read(wallet.join("data.sqlite")).unwrap(), b"db");
        assert_eq!(
            std::fs::read(wallet.join("zec/lrz/data.sqlite")).unwrap(),
            b"other"
        );
    }

    /// A crash mid-move leaves some artifacts at the root and some already moved. That is not
    /// the ambiguous case - each artifact is in exactly one place - so the next start finishes
    /// the job.
    #[test]
    fn an_interrupted_migration_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("default");
        make_legacy_wallet(&wallet);
        let engine = wallet.join("zec").join("lrz");
        std::fs::create_dir_all(&engine).unwrap();
        std::fs::rename(wallet.join("data.sqlite"), engine.join("data.sqlite")).unwrap();
        let config = config_with(dir.path(), "");

        let moved = migrate(&config).expect("a half-done migration resumes");
        assert_eq!(moved.len(), 1);
        assert!(
            !moved[0].artifacts.iter().any(|a| a == "data.sqlite"),
            "the already-moved database is not moved twice: {:?}",
            moved[0].artifacts
        );
        assert_migrated(&wallet);
    }

    #[test]
    fn the_read_only_fallback_finds_an_unmigrated_wallet_without_moving_it() {
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        let config = config_with(dir.path(), "");
        let entry = &config.wallets["default"];

        assert_eq!(engine_dir_for_reading(entry), dir.path().join("default"));
        assert!(awaits_migration(&entry.dir, entry.coin));
        assert!(
            !dir.path().join("default").join("zec").exists(),
            "a read-only command must not migrate anything"
        );
    }

    #[test]
    fn the_read_only_fallback_never_shadows_a_migrated_wallet() {
        let dir = tempfile::tempdir().unwrap();
        make_legacy_wallet(&dir.path().join("default"));
        let config = config_with(dir.path(), "");
        migrate(&config).unwrap();
        // A leftover database at the old path must not win once the real one has moved.
        std::fs::write(dir.path().join("default").join("data.sqlite"), b"stale").unwrap();

        let entry = &config.wallets["default"];
        assert_eq!(engine_dir_for_reading(entry), entry.engine_dir());
        assert!(!awaits_migration(&entry.dir, entry.coin));
    }
}
