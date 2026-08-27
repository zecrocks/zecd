//! Fleet **scan domains**: many watch-only wallets sharing one wallet database, one actor, and
//! one scan.
//!
//! # Why a shard exists
//!
//! zecd's sharing unit was the wallet: one `WalletDb`, one actor, one scan, one set of
//! note-commitment trees each. Trial decryption is per (viewing key, output) by the protocol's
//! design and cannot be shared away - but everything wrapped around it can be, and none of it was.
//! At N monitored wallets a daemon paid N block fetches, N tree-append passes, N SQLite writers
//! and N enhancement loops for one chain.
//!
//! librustzcash already scans **multi-account**: `scan_cached_blocks` reads every account's UFVK
//! out of the database, builds one `ScanningKeys` over the whole set, and trial-decrypts each
//! block once against all of them, batched and on rayon. So the fix is not a new scanner - it is
//! putting many accounts in one database. A shard is exactly that: `shard_size` view wallets, one
//! account apiece, behind a single actor. One fetch, one decryption pass, one tree set, one
//! enhancement backlog, for all of them.
//!
//! # Why shards rather than one database for everything
//!
//! Sharding costs nothing in crypto - the work is the sum over keys either way - so it buys
//! nothing to make shards large, and two things to keep them bounded:
//!
//! 1. **Onboarding blast radius.** `zcash_client_sqlite`'s `add_account` rewinds the database to
//!    the new account's birthday: it truncates note-commitment-tree data above the pruning floor
//!    and requeues everything above `birthday - 1` as a `Historic` rescan. In a shared database
//!    that means onboarding one wallet with a deep birthday makes *every* account in it re-scan.
//!    Confining that to one shard - and placing deep-birthday arrivals in a fresh shard of their
//!    own ([`place_members`]) - is what keeps onboarding from disturbing the wallets already
//!    running.
//! 2. **Blast radius generally.** One SQLite writer serializes per shard, `get_wallet_summary` is
//!    O(accounts in the database), and a corrupt database or an unrecoverable reorg halts one
//!    shard rather than the fleet.
//!
//! # Placement is recorded by the database, not by a side-file
//!
//! A member's shard is *where its account lives*, read back at startup from the accounts each
//! shard database holds. There is no placement file to keep in sync with reality, and nothing to
//! lose: a member with no account anywhere is simply placed and imported. This is also what keeps
//! the statelessness invariant - the only operator-supplied datum is the manifest (a viewing key,
//! a birthday, a name), and everything else is rebuilt from it plus the chain.
//!
//! # Scope
//!
//! Shard members are **watch-only and shielded-only**. Spending is unchanged and stays where it
//! was: one conventional wallet, its own database, its own actor, every existing invariant. A
//! transparent-enabled fleet wallet is refused at config time rather than half-supported - the
//! transparent matcher keeps per-account gap windows, pre-exposure progress and recovery horizons,
//! and generalizing that to K accounts is its own piece of work.

use std::collections::BTreeMap;

use anyhow::{anyhow, Context as _};
use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, AccountPurpose, WalletRead as _, WalletWrite as _,
};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::BlockHeight;

use crate::network::ZNetwork;
use crate::wallet::open::WriteDb;

/// One view wallet hosted in a shard: the operator-supplied triple, and nothing else.
///
/// This is the whole of a fleet wallet's identity. It is key material plus a name, exactly the
/// class of datum `keys.toml` holds for a conventional wallet, so keeping it in a manifest
/// respects the statelessness invariant: balances, history and addresses are all rebuilt from the
/// viewing key and the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardMember {
    /// The wallet name, as `/wallet/<name>` addresses it. Unique across the whole daemon.
    pub name: String,
    /// The Unified Full Viewing Key, in its encoded form.
    pub ufvk: String,
    /// The height to scan this wallet from.
    pub birthday: BlockHeight,
}

impl ShardMember {
    /// Decode this member's viewing key for the configured network.
    pub fn decode_ufvk(&self, network: ZNetwork) -> anyhow::Result<UnifiedFullViewingKey> {
        UnifiedFullViewingKey::decode(&network, &self.ufvk).map_err(|e| {
            anyhow!(
                "wallet '{}': its viewing key is not a valid {} UFVK: {e}",
                self.name,
                network.name()
            )
        })
    }
}

/// What a shard's database already holds, matched against what its manifest says it should.
pub struct Reconciled {
    /// Members whose account exists: wallet name -> account.
    pub adopted: BTreeMap<String, AccountUuid>,
    /// Members with no account yet. Importing one needs the tree state at its birthday, so it
    /// cannot happen until the actor is connected - see the actor's shard-import pass.
    pub pending: Vec<ShardMember>,
}

/// Match a shard's manifest members against the accounts already in its database.
///
/// An account is a member's when their **viewing keys agree**, not when their names do: the name
/// is a label, the key is the identity. That makes this the fleet's account-to-keys binding
/// check. The manifest entry is the pin, and an account carrying a different key under a member's
/// name is tampering evidence, reported as an error rather than quietly re-imported under a new
/// account.
///
/// Idempotent, so a restart adopts everything and imports nothing.
pub fn reconcile_accounts(
    network: ZNetwork,
    db: &WriteDb,
    members: &[ShardMember],
) -> anyhow::Result<Reconciled> {
    // Index the database's accounts by their encoded viewing key, and by name, once.
    let mut by_ufvk: BTreeMap<String, AccountUuid> = BTreeMap::new();
    let mut by_name: BTreeMap<String, String> = BTreeMap::new();
    for id in db.get_account_ids().context("listing shard accounts")? {
        let Some(account) = db.get_account(id).context("reading a shard account")? else {
            continue;
        };
        let Some(ufvk) = account.ufvk() else {
            // An account with no viewing key cannot serve a view wallet. Never produced here
            // (every member is imported from a UFVK), so this is defensive only.
            continue;
        };
        let encoded = ufvk.encode(&network);
        if let Some(name) = account.name() {
            by_name.insert(name.to_string(), encoded.clone());
        }
        by_ufvk.insert(encoded, id);
    }

    let mut adopted = BTreeMap::new();
    let mut pending = Vec::new();
    for member in members {
        // Validate the manifest's key before anything else, so a typo is reported against the
        // manifest rather than surfacing later as a mysteriously absent account.
        let encoded = member.decode_ufvk(network)?.encode(&network);
        match by_ufvk.get(&encoded) {
            Some(id) => {
                adopted.insert(member.name.clone(), *id);
            }
            None => {
                // The name is taken by an account holding a *different* key. Re-importing would
                // silently serve this wallet name from a second account while the first kept
                // scanning, so refuse: either the manifest entry was edited to a new key (the
                // wallet should be onboarded under a new name) or the database was tampered with.
                if by_name.contains_key(&member.name) {
                    return Err(anyhow!(
                        "wallet '{}' is already an account in this shard under a different \
                         viewing key: its manifest entry and the wallet database disagree about \
                         which wallet it is. Refusing to import a second account under the same \
                         name - remove the manifest entry, or onboard the new key under a new \
                         name.",
                        member.name
                    ));
                }
                pending.push(member.clone());
            }
        }
    }
    Ok(Reconciled { adopted, pending })
}

/// Import one member as a watch-only account, at the birthday `birthday` describes.
///
/// `AccountPurpose::ViewOnly` is what makes the actor report the wallet watch-only, which is what
/// disables every spending RPC for it. Shard members are never anything else: the fleet exists to
/// *monitor*, and spending stays with the one conventional wallet.
pub fn import_member(
    db: &mut WriteDb,
    member: &ShardMember,
    birthday: &AccountBirthday,
) -> anyhow::Result<AccountUuid> {
    let network = *db.params();
    let ufvk = member.decode_ufvk(network)?;
    let account = db
        .import_account_ufvk(
            &member.name,
            &ufvk,
            birthday,
            AccountPurpose::ViewOnly,
            None,
        )
        .with_context(|| format!("importing wallet '{}' into its shard", member.name))?;
    Ok(account.id())
}

/// Assign members that have no account anywhere to a shard.
///
/// Two rules, both consequences of `add_account` rewinding a shared database to the new account's
/// birthday:
///
/// * a shard is **sealed** once it holds `shard_size` accounts, so the per-shard cost of a rewind
///   stays bounded; and
/// * an arrival whose birthday is more than `cohort_depth` blocks below a shard's oldest existing
///   birthday starts a **new** shard instead of joining it. Otherwise one deep-birthday wallet
///   would drag a whole shard of caught-up wallets back through a rescan, where in a fresh shard
///   it re-scans only against its own key - over the same blocks the daemon is already fetching.
///
/// `existing` maps each shard index to what it currently holds: its account count and the lowest
/// birthday among them. Returns, per member, the shard index it should be imported into; indices
/// at or above `existing.len()` are new shards.
///
/// Pure, so the placement rules are unit-testable without a database or a chain.
pub fn place_members(
    existing: &[ShardState],
    members: &[ShardMember],
    shard_size: usize,
    cohort_depth: u32,
) -> Vec<usize> {
    let mut shards: Vec<ShardState> = existing.to_vec();
    let mut out = Vec::with_capacity(members.len());
    for member in members {
        let height = u32::from(member.birthday);
        // Prefer the newest shard that has room and whose cohort this birthday belongs to, so
        // wallets onboarded together land together and a later arrival does not reopen an old
        // shard that has long since caught up.
        let target = shards
            .iter()
            .enumerate()
            .rev()
            .find(|(_, shard)| {
                shard.accounts < shard_size
                    && shard
                        .lowest_birthday
                        .is_none_or(|lowest| height + cohort_depth >= lowest)
            })
            .map(|(index, _)| index);
        let index = match target {
            Some(index) => index,
            None => {
                shards.push(ShardState {
                    accounts: 0,
                    lowest_birthday: None,
                });
                shards.len() - 1
            }
        };
        let shard = &mut shards[index];
        shard.accounts += 1;
        shard.lowest_birthday = Some(shard.lowest_birthday.map_or(height, |l| l.min(height)));
        out.push(index);
    }
    out
}

/// What one shard currently holds, for [`place_members`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardState {
    /// Accounts already in this shard.
    pub accounts: usize,
    /// The lowest birthday among them, or `None` for an empty shard (which accepts anything).
    pub lowest_birthday: Option<u32>,
}

/// The directory name for shard `index`, under the fleet directory. Zero-padded so a directory
/// listing sorts in shard order.
pub fn shard_dir_name(index: usize) -> String {
    format!("shard-{index:04}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, birthday: u32) -> ShardMember {
        ShardMember {
            name: name.to_string(),
            ufvk: String::new(),
            birthday: BlockHeight::from_u32(birthday),
        }
    }

    #[test]
    fn shard_dir_names_sort_in_shard_order() {
        let mut names = [shard_dir_name(10), shard_dir_name(2), shard_dir_name(1)];
        names.sort();
        assert_eq!(names, ["shard-0001", "shard-0002", "shard-0010"]);
    }

    /// The ordinary case: wallets onboarded together fill one shard until it is full, then open
    /// the next. Nothing about a full shard is reopened later.
    #[test]
    fn members_fill_a_shard_before_opening_the_next() {
        let members: Vec<_> = (0..5).map(|i| member(&format!("w{i}"), 1_000)).collect();
        assert_eq!(place_members(&[], &members, 2, 100), vec![0, 0, 1, 1, 2]);
    }

    /// A deep-birthday arrival starts its own shard rather than joining one that has caught up.
    /// Joining would rewind that shard to the new birthday and re-scan every wallet in it against
    /// every key; alone, it re-scans only against its own.
    #[test]
    fn a_deep_birthday_arrival_starts_a_new_shard() {
        let existing = [ShardState {
            accounts: 1,
            lowest_birthday: Some(2_000_000),
        }];
        // Within the cohort depth: joins the existing shard, which rewinds only slightly.
        assert_eq!(
            place_members(&existing, &[member("near", 1_999_500)], 128, 1_000),
            vec![0]
        );
        // Far below it: its own shard.
        assert_eq!(
            place_members(&existing, &[member("deep", 1_000_000)], 128, 1_000),
            vec![1]
        );
    }

    /// A birthday *above* a shard's lowest is always in-cohort: importing it rewinds to a height
    /// that shard has already scanned past cheaply, and never below what it already holds.
    #[test]
    fn a_recent_birthday_joins_the_newest_open_shard() {
        let existing = [
            ShardState {
                accounts: 1,
                lowest_birthday: Some(1_000_000),
            },
            ShardState {
                accounts: 1,
                lowest_birthday: Some(2_000_000),
            },
        ];
        assert_eq!(
            place_members(&existing, &[member("new", 2_500_000)], 128, 1_000),
            vec![1],
            "the newest open shard, not the oldest"
        );
    }

    /// A full shard is skipped even when the cohort matches, so `shard_size` actually bounds the
    /// per-shard rewind cost.
    #[test]
    fn a_full_shard_is_never_reopened() {
        let existing = [ShardState {
            accounts: 4,
            lowest_birthday: Some(1_000_000),
        }];
        assert_eq!(
            place_members(&existing, &[member("new", 1_000_000)], 4, 1_000),
            vec![1]
        );
    }

    /// Placement of a batch accounts for the members placed earlier in the same batch - otherwise
    /// onboarding 500 wallets at once would put all of them in the first shard with room.
    #[test]
    fn a_batch_fills_shards_as_it_places_them() {
        let existing = [ShardState {
            accounts: 1,
            lowest_birthday: Some(1_000),
        }];
        let members: Vec<_> = (0..4).map(|i| member(&format!("w{i}"), 1_000)).collect();
        assert_eq!(place_members(&existing, &members, 2, 100), vec![0, 1, 1, 2]);
    }
}
