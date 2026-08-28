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
use crate::wallet::CoinWallet;

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

/// The first shard index at or after `from` whose directory does not exist under `fleet_dir`,
/// with that directory. A fresh shard must never adopt an existing directory: one can be on
/// disk without being registered with the manager (its manifests were removed, or a previous
/// spawn failed after creating it), and in the registered case it belongs to a RUNNING actor -
/// deriving the name from the in-memory shard count would reuse it, in the worst case putting a
/// second single-writer actor over a live shard's database.
fn next_free_shard_dir(fleet_dir: &Path, from: usize) -> (usize, PathBuf) {
    let mut index = from;
    loop {
        let dir = fleet_dir.join(shard::shard_dir_name(index));
        if !dir.exists() {
            return (index, dir);
        }
        index += 1;
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

    /// A new shard's directory must come from the disk, not the manager's shard count: a
    /// directory can exist without a manager entry (emptied manifests, a crashed spawn), and in
    /// the worst case the count-named directory belongs to a shard that is RUNNING.
    #[test]
    fn a_new_shard_never_adopts_an_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        // Nothing on disk: the requested index is free.
        assert_eq!(
            next_free_shard_dir(dir.path(), 0),
            (0, dir.path().join(shard::shard_dir_name(0)))
        );
        // shard-0000 and shard-0001 exist (say, only shard-0001 is registered, so the manager
        // holds ONE entry and would have named the new shard shard-0001 - the running one).
        for index in [0usize, 1] {
            std::fs::create_dir_all(dir.path().join(shard::shard_dir_name(index))).unwrap();
        }
        assert_eq!(
            next_free_shard_dir(dir.path(), 1),
            (2, dir.path().join(shard::shard_dir_name(2)))
        );
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

    /// A manager over one shard that already holds `member`, with an inert handle standing in for
    /// its actor. Enough to exercise placement's "already there" branch without a chain.
    fn manager_holding(member: &str) -> FleetManager {
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let template = ShardTemplate {
            network: crate::network::ZNetwork::Test,
            hub: crate::chain::hub::ChainHub::new(
                crate::backend::resolve("zebra://127.0.0.1:18234", crate::network::ZNetwork::Test)
                    .expect("a loopback zebra endpoint resolves"),
                std::time::Duration::from_secs(1),
            ),
            sync_interval: std::time::Duration::from_secs(60),
            rebroadcast_interval: std::time::Duration::from_secs(60),
            reconnect_base: std::time::Duration::from_secs(1),
            reconnect_max: std::time::Duration::from_secs(2),
            confirmations_policy: Default::default(),
            orchard_action_limit: 0,
            target_note_count: crate::config::DEFAULT_TARGET_NOTE_COUNT,
            min_split_output_value: crate::config::DEFAULT_MIN_SPLIT_OUTPUT_VALUE,
            enabled_pools: crate::pools::ReceiverSet::single(crate::pools::Receiver::Orchard),
            default_receivers: crate::pools::ReceiverSet::single(crate::pools::Receiver::Orchard),
            shutdown,
        };
        let manager = FleetManager::new(FleetConfig::default(), template);
        manager.register_shard(
            PathBuf::from("shard-0000"),
            crate::wallet::WalletHandle::for_test(
                member,
                crate::network::ZNetwork::Test,
                Default::default(),
            ),
            vec![member.to_string()],
            Some(1),
        );
        manager
    }

    /// Loading a wallet whose account is still in its shard must be a **rename, not an import**.
    ///
    /// `unloadwallet` deletes nothing - the manifest and the account stay, and the shard never
    /// stops scanning for it - so a subsequent `loadwallet` has nothing to import. Handing the
    /// member to the actor again asks for a second account under one name, which the actor
    /// refuses; the wallet then cannot be reloaded at all without restarting the daemon, which is
    /// precisely what these RPCs exist to avoid. (Caught by the fleet e2e's unload/load
    /// round-trip; pinned here because that costs ten minutes of CI to learn.)
    #[tokio::test]
    async fn reloading_a_wallet_already_in_a_shard_does_not_re_import_it() {
        let manager = manager_holding("view-0000");
        let member = ShardMember {
            name: "view-0000".to_string(),
            ufvk: "uview1".to_string(),
            birthday: BlockHeight::from_u32(1),
        };
        // The stand-in handle's command channel is inert, so an import attempt would fail here.
        // Reaching a handle at all is the assertion.
        let handle = manager
            .place(member)
            .await
            .expect("a wallet already in a shard is reloaded, not re-imported");
        assert_eq!(handle.name, "view-0000");
        assert_eq!(
            manager.shards(),
            1,
            "reloading must not open a second shard"
        );
    }

    /// The counterpart: a wallet that is *not* in any shard is a genuine arrival, so placement
    /// must reach the import path rather than silently serving a handle for an account that does
    /// not exist.
    #[tokio::test]
    async fn placing_an_unknown_wallet_is_not_treated_as_a_reload() {
        let manager = manager_holding("view-0000");
        let member = ShardMember {
            name: "brand-new".to_string(),
            ufvk: "uview1".to_string(),
            birthday: BlockHeight::from_u32(1),
        };
        // The stand-in handle's command channel is inert, so the import attempt fails - which is
        // exactly the evidence that this took the import path and not the reload shortcut.
        assert!(
            manager.place(member).await.is_err(),
            "an unknown wallet must be imported, not served as a rename"
        );
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

// ---------------------------------------------------------------------------
// Runtime onboarding
// ---------------------------------------------------------------------------

/// Everything needed to onboard a view wallet **while the daemon runs**: place it into a shard,
/// start scanning for it, and serve it at `/wallet/<name>` - without a restart.
///
/// A fleet that can only grow by editing a config file and restarting is not a fleet; every
/// arrival would cost every wallet in the daemon a stop and a re-sync. So the pieces a shard
/// actor is built from are kept here, and `createwallet` uses them.
///
/// The manager is deliberately thin: it holds the actor template, the live shards, and the tasks
/// it spawned. Placement, reconciliation and import are the same code the startup path uses.
pub struct FleetManager {
    config: crate::config::FleetConfig,
    /// How to build a shard actor. Everything in it is daemon-wide except the shard's own name,
    /// directory and members.
    template: ShardTemplate,
    /// The live shards, in index order.
    shards: std::sync::Mutex<Vec<ShardRuntime>>,
    /// Actors this manager spawned after startup. `Node::shutdown` drains them, so a wallet
    /// onboarded at runtime gets the same clean stop as one loaded at boot - without this, a
    /// shard could be killed mid-write when the process exits.
    tasks: std::sync::Mutex<Vec<(String, tokio::task::JoinHandle<()>)>>,
    /// Serializes onboarding end to end (`onboard` holds it across `place`'s awaits, which the
    /// `shards` lock - a std `Mutex` - cannot span). Placement is a read-decide-act over the
    /// shard set: two concurrent `createwallet`s could otherwise both conclude "no shard has
    /// room", both derive the same new shard index, and spawn two single-writer actors over one
    /// database. Onboarding is a rare operator action, so serializing it costs nothing.
    onboarding: tokio::sync::Mutex<()>,
}

/// The daemon-wide half of a shard actor's configuration.
#[derive(Clone)]
pub struct ShardTemplate {
    pub network: crate::network::ZNetwork,
    pub hub: std::sync::Arc<crate::chain::hub::ChainHub>,
    pub sync_interval: std::time::Duration,
    pub rebroadcast_interval: std::time::Duration,
    pub reconnect_base: std::time::Duration,
    pub reconnect_max: std::time::Duration,
    pub confirmations_policy: zcash_client_backend::data_api::wallet::ConfirmationsPolicy,
    pub orchard_action_limit: usize,
    pub target_note_count: usize,
    pub min_split_output_value: u64,
    pub enabled_pools: crate::pools::ReceiverSet,
    pub default_receivers: crate::pools::ReceiverSet,
    pub shutdown: tokio::sync::watch::Sender<bool>,
}

/// One running shard: enough to add a member to it and to mint that member's handle.
struct ShardRuntime {
    dir: PathBuf,
    /// The wallets placed here, whether or not their accounts have been imported yet.
    ///
    /// Tracked by the manager rather than read back from the actor's published account map,
    /// because the two differ exactly when it matters: a member is *placed* the moment the actor
    /// accepts it and *imported* one connected pass later. Consulting the published map would
    /// make a reload racy against that window.
    members: std::collections::BTreeSet<String>,
    /// Any handle belonging to this shard. A shard's handles differ only in their name - they
    /// share the actor's command channel and published status - so a new member's handle is this
    /// one with a different name. That is also why a member is servable the instant it is
    /// accepted, before its account exists: the account arrives on the published map.
    prototype: crate::wallet::WalletHandle,
    accounts: usize,
    lowest_birthday: Option<u32>,
}

/// Why an onboarding request was refused.
#[derive(Debug)]
pub enum OnboardError {
    /// The name is already served (a configured wallet, or another fleet wallet).
    NameTaken(String),
    /// The name cannot be addressed as `/wallet/<name>`.
    BadName(String),
    /// The viewing key does not decode for this network.
    BadKey(String),
    /// Something failed while placing or starting the wallet.
    Failed(anyhow::Error),
}

impl std::fmt::Display for OnboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnboardError::NameTaken(name) => {
                write!(f, "a wallet named '{name}' is already loaded")
            }
            OnboardError::BadName(why) => f.write_str(why),
            OnboardError::BadKey(why) => f.write_str(why),
            OnboardError::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

impl FleetManager {
    pub fn new(config: crate::config::FleetConfig, template: ShardTemplate) -> Self {
        FleetManager {
            config,
            template,
            shards: std::sync::Mutex::new(Vec::new()),
            tasks: std::sync::Mutex::new(Vec::new()),
            onboarding: tokio::sync::Mutex::new(()),
        }
    }

    /// Record a shard the startup path already started, so runtime onboarding can place wallets
    /// into it rather than always opening a new one.
    pub fn register_shard(
        &self,
        dir: PathBuf,
        prototype: crate::wallet::WalletHandle,
        members: Vec<String>,
        lowest_birthday: Option<u32>,
    ) {
        self.lock_shards().push(ShardRuntime {
            dir,
            accounts: members.len(),
            members: members.into_iter().collect(),
            prototype,
            lowest_birthday,
        });
    }

    /// See [`next_free_shard_dir`].
    fn next_shard_dir(&self, from: usize) -> (usize, PathBuf) {
        next_free_shard_dir(&self.config.dir, from)
    }

    /// The manifest directory this fleet reads.
    pub fn manifest_dir(&self) -> &Path {
        &self.config.manifest_dir
    }

    /// How many shards this fleet currently has.
    pub fn shards(&self) -> usize {
        self.lock_shards().len()
    }

    /// Take the actors spawned after startup, for the shutdown path to await.
    pub fn take_tasks(&self) -> Vec<(String, tokio::task::JoinHandle<()>)> {
        std::mem::take(&mut self.lock_tasks())
    }

    /// Onboard a view wallet: write its manifest, place it into a shard (starting one if none has
    /// room), and register it so `/wallet/<name>` serves it immediately.
    ///
    /// The wallet is servable before its account exists - balances read zero and its scan begins
    /// on the shard's next connected pass, exactly as a wallet loaded at boot behaves before it
    /// catches up. `persist` writes the manifest; a wallet being *re*-loaded skips it.
    pub async fn onboard(
        &self,
        registry: &crate::wallet::WalletRegistry,
        member: ShardMember,
        persist: bool,
    ) -> Result<(), OnboardError> {
        // One onboarding at a time, held to the end: the name check, the placement decision and
        // the registry insert are a single read-decide-act, and interleaving two of them can
        // double-place a name or double-open a shard (see the field doc).
        let _onboarding = self.onboarding.lock().await;
        if registry.contains(&member.name) {
            return Err(OnboardError::NameTaken(member.name));
        }
        if let Err(e) = check_wallet_name(&member.name, Path::new(&member.name)) {
            return Err(OnboardError::BadName(e.to_string()));
        }
        // Decode before anything is written: a bad key must not leave a manifest behind that
        // would then fail every subsequent startup.
        member
            .decode_ufvk(self.template.network)
            .map_err(|e| OnboardError::BadKey(format!("{e:#}")))?;

        if persist {
            self.write_manifest(&member).map_err(OnboardError::Failed)?;
        }
        match self.place(member.clone()).await {
            Ok(handle) => {
                registry.insert(CoinWallet::Zcash(handle));
                Ok(())
            }
            Err(e) => {
                // Don't leave a manifest for a wallet that never started: the next restart would
                // try to import it again with no explanation of why it is not being served.
                if persist {
                    let _ = std::fs::remove_file(self.manifest_path(&member.name));
                }
                Err(OnboardError::Failed(e))
            }
        }
    }

    /// Place `member` into a shard with room, opening a new shard when none has any, and return
    /// its handle.
    async fn place(&self, member: ShardMember) -> anyhow::Result<crate::wallet::WalletHandle> {
        // Already in a shard? Then this is a *reload*, not an import: `unloadwallet` removes the
        // name from the RPC surface and deletes nothing, so the account is still there and the
        // shard has never stopped scanning for it. Handing it to the actor again would be asking
        // for a second account under one name, which the actor rightly refuses - so serving it is
        // a rename of any handle from that shard, exactly as onboarding is.
        if let Some(prototype) = self.shard_holding(&member.name) {
            tracing::info!(wallet = %member.name, "reloaded a view wallet already in a shard");
            return Ok(prototype.sibling(member.name));
        }
        let existing: Vec<ShardState> = self
            .lock_shards()
            .iter()
            .map(|s| ShardState {
                accounts: s.accounts,
                lowest_birthday: s.lowest_birthday,
            })
            .collect();
        let index = shard::place_members(
            &existing,
            std::slice::from_ref(&member),
            self.config.shard_size,
            self.config.cohort_depth,
        )[0];

        let birthday = u32::from(member.birthday);
        if index < existing.len() {
            // An existing shard: hand the member to its actor, which imports it on its next
            // connected pass (an import needs the tree state below the birthday).
            let (prototype, dir) = {
                let shards = self.lock_shards();
                let shard = &shards[index];
                (shard.prototype.clone(), shard.dir.clone())
            };
            prototype.add_shard_member(member.clone()).await?;
            let mut shards = self.lock_shards();
            shards[index].accounts += 1;
            shards[index].members.insert(member.name.clone());
            shards[index].lowest_birthday = Some(
                shards[index]
                    .lowest_birthday
                    .map_or(birthday, |l| l.min(birthday)),
            );
            tracing::info!(
                wallet = %member.name,
                shard = %dir.display(),
                "onboarded a view wallet into a running shard"
            );
            return Ok(prototype.sibling(member.name));
        }

        // No shard has room (or none exists): start one. Its directory is derived from what is
        // on DISK, not from the in-memory shard count: startup registers only shards that had
        // manifested members, so a directory can exist (an emptied shard, a crashed spawn's
        // leftovers) without a manager entry - and naming by count would then reuse it,
        // in the worst case putting a second single-writer actor over a running shard's
        // database. The scan is safe against concurrent onboarding because `onboard` serializes
        // callers.
        let (index, dir) = self.next_shard_dir(index);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating shard directory {}", dir.display()))?;
        let name = shard::shard_dir_name(index);
        let cfg = self
            .template
            .actor_config(&name, &dir, vec![member.clone()]);
        let (handles, task) = crate::wallet::actor::spawn_shard(cfg)
            .await
            .with_context(|| format!("starting fleet shard '{name}'"))?;
        let handle = handles
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("a shard must produce a handle per member"))?;
        self.lock_tasks().push((name.clone(), task));
        self.lock_shards().push(ShardRuntime {
            dir,
            members: std::iter::once(member.name.clone()).collect(),
            prototype: handle.clone(),
            accounts: 1,
            lowest_birthday: Some(birthday),
        });
        tracing::info!(wallet = %member.name, shard = %name, "onboarded a view wallet into a new shard");
        Ok(handle)
    }

    /// A handle from the shard `name` is already placed in, if any.
    fn shard_holding(&self, name: &str) -> Option<crate::wallet::WalletHandle> {
        self.lock_shards()
            .iter()
            .find(|shard| shard.members.contains(name))
            .map(|shard| shard.prototype.clone())
    }

    fn manifest_path(&self, name: &str) -> PathBuf {
        self.config.manifest_dir.join(format!("{name}.toml"))
    }

    fn write_manifest(&self, member: &ShardMember) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.config.manifest_dir).with_context(|| {
            format!(
                "creating the fleet manifest directory {}",
                self.config.manifest_dir.display()
            )
        })?;
        let path = self.manifest_path(&member.name);
        if path.exists() {
            return Err(anyhow!(
                "a manifest for '{}' already exists at {}",
                member.name,
                path.display()
            ));
        }
        std::fs::write(
            &path,
            format!(
                "# Written by zecd createwallet.\nufvk = \"{}\"\nbirthday = {}\n",
                member.ufvk,
                u32::from(member.birthday)
            ),
        )
        .with_context(|| format!("writing the manifest {}", path.display()))
    }

    /// The `RwLock`/`Mutex` critical sections here are all short and cannot leave a half-built
    /// value behind, so recover from a poisoned lock instead of taking the daemon down.
    fn lock_shards(&self) -> std::sync::MutexGuard<'_, Vec<ShardRuntime>> {
        self.shards.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_tasks(&self) -> std::sync::MutexGuard<'_, Vec<(String, tokio::task::JoinHandle<()>)>> {
        self.tasks.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ShardTemplate {
    /// A shard actor's configuration: this template plus the shard's own identity and members.
    fn actor_config(
        &self,
        name: &str,
        dir: &Path,
        members: Vec<ShardMember>,
    ) -> crate::wallet::actor::ActorConfig {
        crate::wallet::actor::ActorConfig {
            name: name.to_string(),
            network: self.network,
            engine_dir: dir.to_path_buf(),
            // A shard has no keys.toml: its wallets are watch-only accounts imported from the
            // manifest's viewing keys.
            keys_path: dir.join("keys.toml"),
            hub: std::sync::Arc::clone(&self.hub),
            sync_interval: self.sync_interval,
            rebroadcast_interval: self.rebroadcast_interval,
            reconnect_base: self.reconnect_base,
            reconnect_max: self.reconnect_max,
            age_identity: None,
            auto_unlock: false,
            bootstrap: false,
            confirmations_policy: self.confirmations_policy,
            orchard_action_limit: self.orchard_action_limit,
            // Never consulted - a shard member cannot spend - but carried so a shard actor's
            // config matches a wallet actor's on every field they share.
            target_note_count: self.target_note_count,
            min_split_output_value: self.min_split_output_value,
            // Shard members never spend, so the proving keys would be dead weight.
            orchard_keys: None,
            pipeline_proving: false,
            // Never consulted either: the trust marker is written at send-store time.
            trust_own_transactions: false,
            enabled_pools: self.enabled_pools.clone(),
            default_receivers: self.default_receivers.clone(),
            // Shielded-only - see `crate::wallet::shard`.
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: crate::config::DEFAULT_TRANSPARENT_GAP_LIMIT,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: true,
            transparent_gap_warn_threshold: 5,
            shard_members: members,
            shutdown: self.shutdown.subscribe(),
        }
    }
}
