//! The fleet's on-disk shape: a directory of per-wallet manifests, and the shard databases the
//! wallets in them are scanned in.
//!
//! # Why a manifest directory rather than `[wallets.<name>]`
//!
//! A configured wallet is a TOML table plus its own data directory, `keys.toml` and `zecd init`
//! run. That is right for the handful of wallets zecd was built around and wrong for five
//! thousand: nobody edits a config file with five thousand tables in it, and a wallet arriving at
//! runtime cannot be added to one without restarting the daemon.
//!
//! A fleet wallet is instead one small file naming the only three things a watch-only wallet
//! actually *is* - a name, a viewing key, a birthday:
//!
//! ```toml
//! # <datadir>/wallets.d/acct-00417.toml
//! ufvk = "uview1..."
//! birthday = 2837400
//! ```
//!
//! This is the same class of datum `keys.toml` holds, so it respects the statelessness invariant:
//! it is operator-supplied key material, and balances, history and addresses are all rebuilt from
//! it plus the chain. Which shard a wallet ended up in is deliberately *not* recorded here - that
//! is read back from the shard databases themselves (see [`crate::wallet::shard`]), so there is
//! no placement file that can disagree with reality.
//!
//! The fleet is **additive**. With no manifest directory present, none of this runs and
//! `[wallets.<name>]` behaves exactly as before.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use serde::Deserialize;
use zcash_protocol::consensus::BlockHeight;

use crate::config::FleetConfig;
use crate::wallet::shard::{self, ShardMember, ShardState};

/// A manifest file's contents. `deny_unknown_fields` for the same reason the main config uses it:
/// a mistyped key is a wallet that would silently not be what the operator meant.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    /// The wallet's Unified Full Viewing Key.
    ufvk: String,
    /// The height to scan this wallet from. Required: defaulting it would silently pick either a
    /// full-chain rescan or a tip-only scan that misses the wallet's funds, and both are worse
    /// than saying so.
    birthday: u32,
}

/// Read every wallet manifest in `dir`, in name order.
///
/// The wallet's name is its file stem, so `acct-00417.toml` is `/wallet/acct-00417`. A missing
/// directory is not an error - it is simply a daemon with no fleet, which is every existing
/// deployment. Non-`.toml` entries are ignored so an operator's notes or a partially written
/// `.tmp` file cannot break startup.
pub fn load_manifests(dir: &Path) -> anyhow::Result<Vec<ShardMember>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading the fleet manifest directory {}", dir.display()))?;
    let mut members = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("listing {}", dir.display()))?
            .path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        members.push(read_manifest(&path)?);
    }
    // Name order, so placement (and therefore the shard layout) is reproducible rather than
    // dependent on directory iteration order.
    members.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(dup) = first_duplicate(&members) {
        return Err(anyhow!(
            "two fleet manifests both name the wallet '{dup}' in {}",
            dir.display()
        ));
    }
    Ok(members)
}

/// Read one manifest file into a member.
fn read_manifest(path: &Path) -> anyhow::Result<ShardMember> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("fleet manifest {} has no usable file name", path.display()))?
        .to_string();
    check_wallet_name(&name, path)?;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading fleet manifest {}", path.display()))?;
    let file: ManifestFile = toml::from_str(&text)
        .with_context(|| format!("parsing fleet manifest {}", path.display()))?;
    Ok(ShardMember {
        name,
        ufvk: file.ufvk,
        birthday: BlockHeight::from_u32(file.birthday),
    })
}

/// Reject a manifest file name that cannot serve as a wallet name.
///
/// The name reaches the RPC surface as `/wallet/<name>`, so it is bounded to the characters that
/// survive a URL path segment unambiguously. This is a startup-time refusal rather than a
/// sanitization: a name that had to be rewritten to be routable would not be the name the
/// operator is reconciling against.
fn check_wallet_name(name: &str, path: &Path) -> anyhow::Result<()> {
    if name.is_empty() {
        return Err(anyhow!(
            "fleet manifest {} has an empty name",
            path.display()
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(anyhow!(
            "fleet manifest {} names the wallet '{name}', which is not addressable as \
             /wallet/<name>: use ASCII letters, digits, '-', '_' or '.'",
            path.display()
        ));
    }
    Ok(())
}

/// The first name that appears twice in a name-sorted member list.
fn first_duplicate(members: &[ShardMember]) -> Option<&str> {
    members
        .windows(2)
        .find(|pair| pair[0].name == pair[1].name)
        .map(|pair| pair[0].name.as_str())
}

/// The fleet's shards, each with the members it will serve.
pub struct Layout {
    /// Per shard, in index order: its data directory and its members.
    pub shards: Vec<(PathBuf, Vec<ShardMember>)>,
}

impl Layout {
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// Total wallets across every shard.
    pub fn members(&self) -> usize {
        self.shards.iter().map(|(_, m)| m.len()).sum()
    }
}

/// Work out which shard each manifested wallet belongs to.
///
/// A wallet already imported somewhere stays there - its shard is wherever its account lives, read
/// back from the shard databases by `placed`. Everything else is placed by
/// [`shard::place_members`], which keeps shards bounded and puts deep-birthday arrivals in a shard
/// of their own.
///
/// `placed` maps a wallet name to the shard index holding its account, as discovered by
/// [`discover_placements`]. Pure given that, so the layout rules are testable without databases.
pub fn plan(
    members: Vec<ShardMember>,
    placed: &BTreeMap<String, usize>,
    existing: &[ShardState],
    config: &FleetConfig,
) -> Layout {
    let mut shards: Vec<Vec<ShardMember>> = vec![Vec::new(); existing.len()];
    let mut unplaced = Vec::new();
    for member in members {
        match placed.get(&member.name) {
            Some(&index) if index < shards.len() => shards[index].push(member),
            // A recorded placement past the end of `existing` cannot happen (both come from the
            // same scan), and an unrecorded one is simply a wallet that has never been imported.
            _ => unplaced.push(member),
        }
    }
    for (member, index) in unplaced.iter().zip(shard::place_members(
        existing,
        &unplaced,
        config.shard_size,
        config.cohort_depth,
    )) {
        while shards.len() <= index {
            shards.push(Vec::new());
        }
        shards[index].push(member.clone());
    }
    Layout {
        shards: shards
            .into_iter()
            .enumerate()
            .map(|(index, members)| (config.dir.join(shard::shard_dir_name(index)), members))
            .filter(|(_, members)| !members.is_empty())
            .collect(),
    }
}

/// Read back what shard `index` at `dir` already holds: its account count, the lowest birthday
/// among them, and which manifested wallet each account serves (recorded into `placed`).
///
/// This is the placement record. It is the shard databases themselves rather than a side-file
/// precisely so it cannot disagree with reality: a wallet's shard *is* wherever its account is,
/// and a wallet with no account anywhere is simply one that has not been imported yet.
///
/// Opened read-only, so this never disturbs a database (and never creates one).
pub fn inspect_shard(
    network: crate::network::ZNetwork,
    dir: &Path,
    index: usize,
    placed: &mut BTreeMap<String, usize>,
) -> anyhow::Result<ShardState> {
    use zcash_client_backend::data_api::{Account as _, WalletRead as _};

    let db = crate::wallet::open::open_read(network, dir)?;
    let ids = db.get_account_ids()?;
    let mut lowest_birthday: Option<u32> = None;
    for id in &ids {
        let Some(account) = db.get_account(*id)? else {
            continue;
        };
        if let Some(name) = account.name() {
            placed.insert(name.to_string(), index);
        }
        let birthday = u32::from(db.get_account_birthday(*id)?);
        lowest_birthday = Some(lowest_birthday.map_or(birthday, |l: u32| l.min(birthday)));
    }
    Ok(ShardState {
        accounts: ids.len(),
        lowest_birthday,
    })
}

/// The shard directories that already exist, in index order.
///
/// Only contiguous indices from 0 count: the layout numbers shards densely, so a gap would mean a
/// directory was removed by hand, and silently renumbering around it would move every wallet above
/// the gap into a different shard (and rescan them).
pub fn existing_shard_dirs(fleet_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for index in 0.. {
        let dir = fleet_dir.join(shard::shard_dir_name(index));
        if !dir.is_dir() {
            break;
        }
        dirs.push(dir);
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    fn member(name: &str, birthday: u32) -> ShardMember {
        ShardMember {
            name: name.to_string(),
            ufvk: format!("uview1{name}"),
            birthday: BlockHeight::from_u32(birthday),
        }
    }

    /// A daemon with no fleet directory is every existing deployment: it must load cleanly as an
    /// empty fleet, not fail.
    #[test]
    fn a_missing_manifest_directory_is_an_empty_fleet() {
        let dir = tempfile::tempdir().unwrap();
        let members = load_manifests(&dir.path().join("absent")).unwrap();
        assert!(members.is_empty());
    }

    #[test]
    fn manifests_load_in_name_order_with_the_file_stem_as_the_wallet_name() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "b.toml", "ufvk = \"uview1b\"\nbirthday = 20\n");
        write(dir.path(), "a.toml", "ufvk = \"uview1a\"\nbirthday = 10\n");
        // Ignored: not a manifest. A half-written temp file must not break startup.
        write(dir.path(), "notes.txt", "scratch");
        write(dir.path(), "c.toml.tmp", "garbage");
        let members = load_manifests(dir.path()).unwrap();
        assert_eq!(
            members.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(members[0].ufvk, "uview1a");
        assert_eq!(u32::from(members[1].birthday), 20);
    }

    /// An unknown key is a wallet that is not what the operator meant - the same reason the main
    /// config denies them.
    #[test]
    fn an_unknown_manifest_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "w.toml",
            "ufvk = \"uview1w\"\nbirthday = 1\nbirthdya = 2\n",
        );
        let err = load_manifests(dir.path()).unwrap_err().to_string();
        assert!(err.contains("w.toml"), "{err}");
    }

    /// Omitting the birthday would silently choose between a full-chain rescan and a tip-only
    /// scan that misses the wallet's funds. Both are worse than refusing.
    #[test]
    fn a_manifest_without_a_birthday_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "w.toml", "ufvk = \"uview1w\"\n");
        assert!(load_manifests(dir.path()).is_err());
    }

    #[test]
    fn a_name_that_is_not_routable_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "we ird.toml", "ufvk = \"u\"\nbirthday = 1\n");
        let err = load_manifests(dir.path()).unwrap_err().to_string();
        assert!(err.contains("/wallet/<name>"), "{err}");
    }

    /// A wallet already imported stays in its shard whatever the placement rules would now say -
    /// moving it would mean re-scanning it from its birthday in a different database.
    #[test]
    fn already_placed_wallets_stay_in_their_shard() {
        let config = FleetConfig {
            shard_size: 2,
            ..FleetConfig::default()
        };
        let existing = [
            ShardState {
                accounts: 1,
                lowest_birthday: Some(100),
            },
            ShardState {
                accounts: 1,
                lowest_birthday: Some(100),
            },
        ];
        let placed = BTreeMap::from([("a".to_string(), 1usize), ("b".to_string(), 0usize)]);
        let layout = plan(
            vec![member("a", 100), member("b", 100)],
            &placed,
            &existing,
            &config,
        );
        assert_eq!(layout.shards.len(), 2);
        assert_eq!(layout.shards[0].1[0].name, "b", "shard 0 keeps b");
        assert_eq!(layout.shards[1].1[0].name, "a", "shard 1 keeps a");
    }

    /// New wallets are placed into shards with room, and the layout only lists shards that will
    /// actually serve somebody.
    #[test]
    fn new_wallets_are_placed_and_empty_shards_are_omitted() {
        let config = FleetConfig {
            shard_size: 2,
            ..FleetConfig::default()
        };
        let members = (0..3).map(|i| member(&format!("w{i}"), 500)).collect();
        let layout = plan(members, &BTreeMap::new(), &[], &config);
        assert_eq!(layout.members(), 3);
        assert_eq!(layout.shards.len(), 2, "two shards at shard_size = 2");
        assert_eq!(layout.shards[0].1.len(), 2);
        assert_eq!(layout.shards[1].1.len(), 1);
        assert!(layout.shards[0].0.ends_with("shard-0000"));
        assert!(layout.shards[1].0.ends_with("shard-0001"));
    }

    /// Shard directories are numbered densely; a hand-removed directory truncates the scan rather
    /// than renumbering the shards above it (which would move - and rescan - every wallet in them).
    #[test]
    fn existing_shard_dirs_stop_at_the_first_gap() {
        let dir = tempfile::tempdir().unwrap();
        for index in [0usize, 1, 3] {
            std::fs::create_dir_all(dir.path().join(shard::shard_dir_name(index))).unwrap();
        }
        let dirs = existing_shard_dirs(dir.path());
        assert_eq!(dirs.len(), 2, "0 and 1; 3 is past the gap at 2");
    }
}
