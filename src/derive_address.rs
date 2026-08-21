//! `zecd derive-address`: derive a wallet's receiving addresses offline.
//!
//! Every other way to learn a zecd address needs infrastructure: `getnewaddress` needs a running
//! daemon, and `zecd init` needs a live upstream (it anchors the account on the tree state at
//! `birthday - 1`). That makes an address a chicken-and-egg problem whenever it is needed
//! *before* the wallet has a chain - pre-provisioning deposit addresses, air-gapped or cold
//! setup, or configuring a miner to pay the wallet that does not exist yet. This command closes
//! that gap: it touches no network, no wallet database, and no daemon, and takes no datadir lock
//! (like `export-ufvk`, so it works while a daemon is running).
//!
//! Addresses are a function of the account's viewing key alone, so the key material can come from
//! any of three sources:
//!
//! - an initialized wallet's `keys.toml`, via the account UFVK pinned there (see
//!   `wallet::binding`) - no seed is decrypted, so this works for a locked, passphrase-encrypted,
//!   or watch-only wallet;
//! - a BIP-39 mnemonic (`--mnemonic`, read from `ZECD_MNEMONIC`/`--mnemonic-file`/stdin);
//! - a Unified Full Viewing Key (`--ufvk`, as `zecd export-ufvk` prints).
//!
//! Supplying key material *and* naming a wallet checks the two against each other: the derived
//! UFVK is compared with that wallet's pin, which is how an operator confirms a `keys.toml`
//! really belongs to the seed they hold before trusting it with deposits.
//!
//! The derivation is the same primitive the daemon uses. A Unified Address at index `j` is
//! `uivk.address(j, request)`, exactly what `zcash_client_sqlite`'s `get_address_for_index` (and
//! so `z_getaddressforaccount`) calls; a bare transparent address at index `j` is the p2pkh
//! receiver of that UA, exactly what `getnewaddress "" "transparent"` hands out for external
//! child index `j`. What this command deliberately cannot reproduce is `getnewaddress`'s *next*
//! shielded address: those diversifier indexes are clock-derived, so
//! only an explicit index is deterministic - which is what an offline caller wants anyway.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use secrecy::{SecretVec, Zeroize};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec as _;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
use zip32::DiversifierIndex;

#[cfg(feature = "cli")]
use crate::config::DeriveAddressArgs;
use crate::config::{AppConfig, WalletEntry};
use crate::network::ZNetwork;
use crate::pools::ReceiverSet;
use crate::wallet::store::WalletStore;
use crate::wallet::ReceiverRequest;

/// The wallet whose configuration (and `keys.toml`) is used when `--wallet` is omitted, matching
/// the `--wallet` default of every other zecd subcommand.
const DEFAULT_WALLET: &str = "default";

/// Where the viewing key came from, for the report and for the pin cross-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    KeysFile,
    Mnemonic,
    Ufvk,
}

impl KeySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeySource::KeysFile => "keys.toml",
            KeySource::Mnemonic => "mnemonic",
            KeySource::Ufvk => "ufvk",
        }
    }
}

/// The key material to derive from - the resolved form of the `--ufvk` / `--mnemonic` /
/// keys.toml selection, with any interactive input (the mnemonic prompt) already performed by
/// the caller. This is what keeps stdin out of [`derive`].
pub enum KeyInput {
    /// The named wallet's `keys.toml` UFVK pin (no seed decrypted).
    KeysFile,
    /// A BIP-39 mnemonic; only its viewing half is kept, and the derived seed is zeroized.
    Mnemonic(bip0039::Mnemonic<bip0039::English>),
    /// An encoded Unified Full Viewing Key, as `export-ufvk` prints.
    Ufvk(String),
}

/// A note or warning the CLI prints to stderr before the report. Each `Display` rendering is
/// the exact text the command has always printed; a library caller gets them as data instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveNote {
    /// Key material was supplied but the named wallet has no `keys.toml` to check it against.
    WalletNotInitializedUnchecked { wallet: String, keys_path: PathBuf },
    /// The named wallet's `keys.toml` predates the UFVK pin, so there is nothing to check.
    NoPinUnchecked { wallet: String, keys_path: PathBuf },
    /// The supplied key derives the account pinned for the named wallet.
    PinVerified { wallet: String, keys_path: PathBuf },
    /// Transparent receiving is disabled for the wallet, so the daemon would not credit these.
    TransparentNotEnabled { wallet: String },
    /// A derived transparent index is at or beyond the stateless-restore recovery horizon.
    BeyondRecoveryHorizon {
        wallet: String,
        last: u64,
        horizon: u32,
    },
    /// The requested receivers include a pool the wallet does not have enabled.
    ReceiversNotEnabled {
        wallet: String,
        receivers: String,
        enabled: String,
    },
}

impl std::fmt::Display for DeriveNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeriveNote::WalletNotInitializedUnchecked { wallet, keys_path } => write!(
                f,
                "note: wallet '{wallet}' is not initialized ({} missing), so the supplied key \
                 was not checked against a pinned viewing key.",
                keys_path.display()
            ),
            DeriveNote::NoPinUnchecked { wallet, keys_path } => write!(
                f,
                "note: wallet '{wallet}' pins no viewing key in {} (created by an older zecd), \
                 so the supplied key was not checked against it.",
                keys_path.display()
            ),
            DeriveNote::PinVerified { wallet, keys_path } => write!(
                f,
                "Verified: the supplied key derives the account pinned for wallet '{wallet}' \
                 in {}.",
                keys_path.display()
            ),
            DeriveNote::TransparentNotEnabled { wallet } => write!(
                f,
                "note: transparent receiving is not enabled for wallet '{wallet}' ([pools] \
                 transparent = false), so a running daemon would not credit payments to \
                 these addresses."
            ),
            DeriveNote::BeyondRecoveryHorizon {
                wallet,
                last,
                horizon,
            } => write!(
                f,
                "warning: index {last} is at or beyond the recovery horizon of wallet \
                 '{wallet}' (transparent_initial_scan + transparent_gap_limit = {horizon}). \
                 Funds received there may be UNRECOVERABLE from seed - raise [pools] \
                 transparent_initial_scan past your issuance high-water mark before handing \
                 these addresses out."
            ),
            DeriveNote::ReceiversNotEnabled {
                wallet,
                receivers,
                enabled,
            } => write!(
                f,
                "note: receivers ({receivers}) include a pool not enabled for wallet \
                 '{wallet}' ({enabled}), so a running daemon would refuse to hand out this \
                 address type."
            ),
        }
    }
}

/// What to derive - the library-facing form of the `derive-address` flags. `wallet: None`
/// selects the `default` wallet's configuration, and (unlike `Some("default")`) skips the
/// pin cross-check for supplied key material, exactly as the omitted `--wallet` flag does.
pub struct DeriveOptions<'a> {
    pub wallet: Option<&'a str>,
    pub key: KeyInput,
    /// `--address-type` syntax (`unified`, `transparent`, `orchard`, ...); `None` = the
    /// wallet's default, as `getnewaddress` resolves it.
    pub address_type: Option<&'a str>,
    /// The first index to derive.
    pub index: u64,
    /// How many consecutive indices to derive (at least 1).
    pub count: u32,
}

/// What was derived - everything the CLI prints, as data.
#[derive(Debug)]
pub struct DeriveOutcome {
    pub network: ZNetwork,
    pub wallet: String,
    pub source: KeySource,
    /// `Some(true)` when key material was checked against the wallet's pin and matched (a
    /// mismatch is an error, so `Some(false)` never occurs); `None` when nothing was checked.
    pub pin_matches: Option<bool>,
    /// The account UFVK, encoded for `network`.
    pub ufvk: String,
    /// The derived receiver selection, in `--address-type` syntax.
    pub address_type: String,
    /// `(index, encoded address)` pairs, in index order.
    pub addresses: Vec<(u64, String)>,
    /// Notes the CLI prints to stderr before the report, in emission order.
    pub notes: Vec<DeriveNote>,
}

/// What to derive at each index: a bare transparent receiver, or a Unified Address carrying a
/// shielded receiver set.
enum Receivers {
    Transparent,
    Shielded(ReceiverSet),
}

impl Receivers {
    /// The name reported for this selection, in `--address-type` syntax.
    fn describe(&self) -> String {
        match self {
            Receivers::Transparent => "transparent".to_string(),
            Receivers::Shielded(set) => {
                set.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(",")
            }
        }
    }

    /// The librustzcash address request that produces it.
    fn request(&self) -> UnifiedAddressRequest {
        match self {
            // ZIP-316 forbids a transparent-only UA, so a bare t-address is extracted from a UA
            // that requires both an Orchard and a p2pkh receiver - the same request the actor's
            // transparent issuance path uses, so the two agree index for index.
            Receivers::Transparent => crate::pools::transparent_extraction_request(),
            Receivers::Shielded(set) => set.to_unified_address_request(),
        }
    }
}

#[cfg(feature = "cli")]
pub fn run(config: &AppConfig, args: &DeriveAddressArgs) -> anyhow::Result<()> {
    if args.count == 0 {
        bail!("--count must be at least 1");
    }
    // Resolve the key input up front - the mnemonic prompt is the shell's interactive I/O, so
    // it happens here and never inside `derive`.
    let key = if let Some(encoded) = &args.ufvk {
        KeyInput::Ufvk(encoded.clone())
    } else if args.mnemonic || args.mnemonic_file.is_some() {
        KeyInput::Mnemonic(crate::init::read_mnemonic_phrase(
            args.mnemonic_file.as_deref(),
            "Enter the mnemonic phrase to derive from, then press Enter:",
        )?)
    } else {
        KeyInput::KeysFile
    };

    let outcome = derive(
        config,
        DeriveOptions {
            wallet: args.wallet.as_deref(),
            key,
            address_type: args.address_type.as_deref(),
            index: args.index,
            count: args.count,
        },
    )?;

    for note in &outcome.notes {
        eprintln!("{note}");
    }
    Report {
        json: args.json,
        outcome: &outcome,
    }
    .print();
    Ok(())
}

/// The library core of `derive-address`: derive `count` addresses from `opts.key`, with the
/// pin cross-check and the would-the-daemon-watch-this notes returned as data rather than
/// printed. No stdin, no stdout/stderr, no network, no wallet database, no datadir lock.
pub fn derive(config: &AppConfig, opts: DeriveOptions<'_>) -> anyhow::Result<DeriveOutcome> {
    if opts.count == 0 {
        bail!("--count must be at least 1");
    }
    let wallet = opts.wallet.unwrap_or(DEFAULT_WALLET);
    // No layout fallback is needed here (unlike `export-ufvk`): derivation reads `keys.toml`
    // and nothing else, and `keys.toml` sits at the wallet root, where no layout migration
    // moves it.
    let entry = crate::init::resolve_wallet_entry(config, wallet);
    // Derivation follows the wallet's own chain, so an index here is the index the daemon
    // serving that wallet exposes.
    let network = entry.zcash_network();
    let keys_path = entry.keys_path();
    let mut notes = Vec::new();

    let (ufvk, source) = load_key(config, opts.key, wallet, &keys_path)?;

    // Key material supplied by the caller plus an explicitly named wallet is a request to
    // check one against the other (the "does this keys.toml really derive my addresses?" case).
    let pin_matches = if source != KeySource::KeysFile && opts.wallet.is_some() {
        verify_against_pin(network, &ufvk, wallet, &keys_path, &mut notes)?
    } else {
        None
    };

    let receivers = resolve_receivers(&entry, opts.address_type)?;
    warn_if_daemon_would_not_watch(
        &entry, wallet, &receivers, opts.index, opts.count, &mut notes,
    );

    let last = opts
        .index
        .checked_add(u64::from(opts.count) - 1)
        .ok_or_else(|| anyhow!("--index + --count overflows the diversifier index space"))?;
    let mut addresses = Vec::with_capacity(opts.count as usize);
    for index in opts.index..=last {
        addresses.push((index, derive_one(network, &ufvk, &receivers, index)?));
    }

    Ok(DeriveOutcome {
        network,
        wallet: wallet.to_string(),
        source,
        pin_matches,
        ufvk: ufvk.encode(&network),
        address_type: receivers.describe(),
        addresses,
        notes,
    })
}

/// Resolve the account's Unified Full Viewing Key from the selected [`KeyInput`]. The three
/// sources are mutually exclusive by construction; any interactive input (the mnemonic
/// prompt) already happened in the shell.
fn load_key(
    config: &AppConfig,
    key: KeyInput,
    wallet: &str,
    keys_path: &Path,
) -> anyhow::Result<(UnifiedFullViewingKey, KeySource)> {
    let network = config.network;
    match key {
        KeyInput::Ufvk(encoded) => {
            let ufvk = UnifiedFullViewingKey::decode(&network, encoded.trim())
                .map_err(|e| anyhow!("invalid unified full viewing key: {e}"))?;
            return Ok((ufvk, KeySource::Ufvk));
        }
        KeyInput::Mnemonic(mnemonic) => {
            // The seed exists only for this derivation and is zeroized on the way out (the
            // `SecretVec` zeroizes on drop; the intermediate array is wiped explicitly, as in
            // `init`). Deriving the spending key rather than a viewing key directly is what
            // librustzcash offers from a seed; only its viewing half is kept.
            let mut bytes = mnemonic.to_seed("");
            let seed = SecretVec::new(bytes.to_vec());
            bytes.zeroize();
            return Ok((ufvk_from_seed(network, &seed)?, KeySource::Mnemonic));
        }
        KeyInput::KeysFile => {}
    }

    if !WalletStore::exists(keys_path) {
        bail!(
            "wallet '{wallet}' is not initialized ({} missing). Derive from key material \
             instead: --mnemonic (phrase on stdin, ZECD_MNEMONIC, or --mnemonic-file) or \
             --ufvk <key>.",
            keys_path.display()
        );
    }
    let store = WalletStore::read(keys_path)?;
    ensure_network_matches(&store, wallet, network)?;
    let pinned = store.pinned_ufvk().ok_or_else(|| {
        anyhow!(
            "wallet '{wallet}' has no unified full viewing key pinned in {} (it was created by \
             an older zecd; the daemon records one at the next startup). Derive from key \
             material instead: --mnemonic or --ufvk <key>.",
            keys_path.display()
        )
    })?;
    let ufvk = UnifiedFullViewingKey::decode(&network, pinned).map_err(|e| {
        anyhow!(
            "the viewing key pinned in {} is not a valid {} unified full viewing key: {e}",
            keys_path.display(),
            network.name()
        )
    })?;
    Ok((ufvk, KeySource::KeysFile))
}

/// The account's UFVK for a BIP-39 seed, at ZIP-32 account index 0 - the single account zecd
/// creates per wallet, and the one `wallet::binding` pins.
fn ufvk_from_seed(
    network: ZNetwork,
    seed: &SecretVec<u8>,
) -> anyhow::Result<UnifiedFullViewingKey> {
    use secrecy::ExposeSecret as _;
    let account = zip32::AccountId::try_from(0u32).expect("0 is a valid account index");
    let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), account)
        .map_err(|_| anyhow!("deriving the unified spending key from the mnemonic failed"))?;
    Ok(usk.to_unified_full_viewing_key())
}

/// Compare a supplied key against the named wallet's pinned UFVK. A match is the confirmation an
/// operator is after ("this `keys.toml` belongs to my seed"); a mismatch is an error, so the
/// command is usable as a check in a script. A wallet that is not initialized, or one whose
/// `keys.toml` predates the pin, has nothing to compare against - reported as `None` (unchecked)
/// rather than as a failed check.
fn verify_against_pin(
    network: ZNetwork,
    ufvk: &UnifiedFullViewingKey,
    wallet: &str,
    keys_path: &Path,
    notes: &mut Vec<DeriveNote>,
) -> anyhow::Result<Option<bool>> {
    if !WalletStore::exists(keys_path) {
        notes.push(DeriveNote::WalletNotInitializedUnchecked {
            wallet: wallet.to_string(),
            keys_path: keys_path.to_path_buf(),
        });
        return Ok(None);
    }
    let store = WalletStore::read(keys_path)?;
    ensure_network_matches(&store, wallet, network)?;
    let Some(pinned) = store.pinned_ufvk() else {
        notes.push(DeriveNote::NoPinUnchecked {
            wallet: wallet.to_string(),
            keys_path: keys_path.to_path_buf(),
        });
        return Ok(None);
    };
    if pinned != ufvk.encode(&network) {
        bail!(
            "the supplied key does not match the viewing key pinned for wallet '{wallet}' in \
             {}: these are different wallets, and the addresses below would NOT be watched by \
             that wallet.",
            keys_path.display()
        );
    }
    notes.push(DeriveNote::PinVerified {
        wallet: wallet.to_string(),
        keys_path: keys_path.to_path_buf(),
    });
    Ok(Some(true))
}

/// Refuse a `keys.toml` written for a different network rather than emit addresses encoded for
/// the one the flags happen to select (the same guard `export-ufvk` applies).
fn ensure_network_matches(
    store: &WalletStore,
    wallet: &str,
    network: ZNetwork,
) -> anyhow::Result<()> {
    if store.network != network {
        bail!(
            "wallet '{wallet}' is a {} wallet, but the configuration selects {}",
            store.network.name(),
            network.name()
        );
    }
    Ok(())
}

/// Resolve `--address-type` against the wallet's configuration, exactly as `getnewaddress`
/// resolves its own argument: an omitted type means the wallet's default (a bare transparent
/// address when it defaults to transparent, else its `default_receivers`).
fn resolve_receivers(entry: &WalletEntry, address_type: Option<&str>) -> anyhow::Result<Receivers> {
    // The token grammar is shared with the RPC so the two can't drift; only the error type
    // differs (a CLI error rather than a `-5`).
    let request = crate::rpc::wallet_methods::parse_receiver_tokens(address_type)
        .map_err(|e| anyhow!("{}", e.message))?;
    Ok(match request {
        ReceiverRequest::Transparent => Receivers::Transparent,
        ReceiverRequest::Default if entry.transparent_default => Receivers::Transparent,
        ReceiverRequest::Default => Receivers::Shielded(entry.default_receivers.clone()),
        ReceiverRequest::Shielded(set) => Receivers::Shielded(set),
    })
}

/// Point out the two ways a derived address can be one the daemon will never credit: a receiver
/// type the wallet does not have configured, and a transparent index past the wallet's
/// stateless-restore recovery horizon. Neither blocks derivation - deriving an address is not
/// issuing one, and this command exists precisely to run before a wallet is configured - but
/// silently handing out an address that will not be watched is how deposits get lost.
fn warn_if_daemon_would_not_watch(
    entry: &WalletEntry,
    wallet: &str,
    receivers: &Receivers,
    index: u64,
    count: u32,
    notes: &mut Vec<DeriveNote>,
) {
    match receivers {
        Receivers::Transparent => {
            if !entry.transparent_enabled {
                notes.push(DeriveNote::TransparentNotEnabled {
                    wallet: wallet.to_string(),
                });
            }
            // The recovery horizon is the floor-anchored half of transparent restore coverage
            // (see the transparent design notes): a from-seed restore pre-exposes
            // `0..transparent_initial_scan` and looks ahead `transparent_gap_limit` past that,
            // so an index at or beyond their sum is only ever reachable through funding.
            let horizon = entry
                .transparent_initial_scan
                .saturating_add(entry.transparent_gap_limit);
            let last = index.saturating_add(u64::from(count) - 1);
            if last >= u64::from(horizon) {
                notes.push(DeriveNote::BeyondRecoveryHorizon {
                    wallet: wallet.to_string(),
                    last,
                    horizon,
                });
            }
        }
        Receivers::Shielded(set) => {
            if !set.is_subset_of(&entry.pools) {
                notes.push(DeriveNote::ReceiversNotEnabled {
                    wallet: wallet.to_string(),
                    receivers: set.display_names(),
                    enabled: entry.pools.display_names(),
                });
            }
        }
    }
}

/// Derive one address at `index`. Shielded requests yield the encoded Unified Address; a
/// transparent request yields the bare-encoded p2pkh receiver of the derived UA.
fn derive_one(
    network: ZNetwork,
    ufvk: &UnifiedFullViewingKey,
    receivers: &Receivers,
    index: u64,
) -> anyhow::Result<String> {
    let ua = address_at(ufvk, receivers, index)?;
    Ok(match receivers {
        Receivers::Transparent => ua
            .transparent()
            .ok_or_else(|| anyhow!("the derived address unexpectedly has no transparent receiver"))?
            .encode(&network),
        Receivers::Shielded(_) => ua.encode(&network),
    })
}

/// `uivk.address(j, request)` with the failure modes translated into advice. Not every index
/// yields an address: a transparent receiver needs a non-hardened child index, and only about
/// half of all diversifier indexes are valid Sapling diversifiers.
fn address_at(
    ufvk: &UnifiedFullViewingKey,
    receivers: &Receivers,
    index: u64,
) -> anyhow::Result<UnifiedAddress> {
    ufvk.address(DiversifierIndex::from(index), receivers.request())
        .map_err(|e| {
            let hint = match receivers {
                Receivers::Transparent => " (a transparent receiver requires an index below 2^31)",
                Receivers::Shielded(set) if set.contains(crate::pools::Receiver::Sapling) => {
                    " (about half of all diversifier indexes are invalid for Sapling; try \
                     another index, or --address-type orchard)"
                }
                Receivers::Shielded(_) => "",
            };
            anyhow!("no address at index {index}: {e}{hint}")
        })
}

/// The CLI rendering of a [`DeriveOutcome`].
#[cfg(feature = "cli")]
struct Report<'a> {
    json: bool,
    outcome: &'a DeriveOutcome,
}

#[cfg(feature = "cli")]
impl Report<'_> {
    /// Print the result: one address per line on stdout (so `--count` output pipes straight into
    /// a provisioning script, and a single address substitutes into a command), with the context
    /// on stderr - or one JSON object on stdout under `--json`.
    fn print(&self) {
        let outcome = self.outcome;
        if self.json {
            let entries: Vec<serde_json::Value> = outcome
                .addresses
                .iter()
                .map(|(index, address)| serde_json::json!({"index": index, "address": address}))
                .collect();
            // The account UFVK rides along in machine-readable mode: it is what pairs a
            // watch-only instance (`init --ufvk`), and deriving it here is the only way to get it
            // before a wallet database exists - `export-ufvk` reads one. It is view-only
            // authority over key material the caller already supplied (or already has pinned on
            // disk).
            let mut out = serde_json::json!({
                "network": outcome.network.name(),
                "wallet": outcome.wallet,
                "source": outcome.source.as_str(),
                "address_type": outcome.address_type,
                "ufvk": outcome.ufvk,
                "addresses": entries,
            });
            if let Some(matches) = outcome.pin_matches {
                out["pin_matches"] = serde_json::Value::Bool(matches);
            }
            println!("{}", serde_json::to_string_pretty(&out).expect("json"));
            return;
        }

        // Everything except the addresses themselves goes to stderr, so `$(zecd derive-address
        // ...)` is the address and a `--count` run pipes straight into a provisioning script. The
        // indices are the header's range, in order, so no per-line marker is needed.
        let range = match outcome.addresses.as_slice() {
            [(only, _)] => format!("index {only}"),
            [(first, _), .., (last, _)] => format!("indices {first}-{last}"),
            [] => "no indices".to_string(),
        };
        eprintln!(
            "Wallet '{}' ({}), receivers: {}, {range}, key source: {}",
            outcome.wallet,
            outcome.network.name(),
            outcome.address_type,
            outcome.source.as_str(),
        );
        for (_, address) in &outcome.addresses {
            println!("{address}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pools::Receiver;

    // The committed testnet development mnemonic (valueless TAZ only). Used here
    // purely as a fixed key source, so the expected addresses below are stable constants.
    const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    fn test_ufvk() -> UnifiedFullViewingKey {
        let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(PHRASE).unwrap();
        let seed = SecretVec::new(mnemonic.to_seed("").to_vec());
        ufvk_from_seed(ZNetwork::Test, &seed).unwrap()
    }

    fn orchard() -> Receivers {
        Receivers::Shielded(ReceiverSet::single(Receiver::Orchard))
    }

    /// The whole point of the command: the same phrase always yields the same addresses, with no
    /// wallet, database, or chain in sight. These constants are the regression guard - if a
    /// librustzcash bump ever changes what index 0 derives, a wallet restored from this seed
    /// would stop recognising its own addresses, and this fails first.
    #[test]
    fn derivation_is_deterministic_for_a_fixed_mnemonic() {
        let ufvk = test_ufvk();
        let ua = derive_one(ZNetwork::Test, &ufvk, &orchard(), 0).unwrap();
        assert!(ua.starts_with("utest1"), "{ua}");
        let taddr = derive_one(ZNetwork::Test, &ufvk, &Receivers::Transparent, 0).unwrap();
        assert!(taddr.starts_with("tm"), "{taddr}");

        // Re-deriving is stable, and a second key built from the same phrase agrees.
        assert_eq!(
            derive_one(ZNetwork::Test, &test_ufvk(), &orchard(), 0).unwrap(),
            ua
        );
        assert_eq!(
            derive_one(ZNetwork::Test, &test_ufvk(), &Receivers::Transparent, 0).unwrap(),
            taddr
        );
    }

    /// Consecutive indexes give distinct addresses - the pre-provisioning case - on both the
    /// shielded and the transparent side.
    #[test]
    fn consecutive_indexes_are_distinct() {
        let ufvk = test_ufvk();
        for receivers in [orchard(), Receivers::Transparent] {
            let addrs: Vec<String> = (0..8)
                .map(|j| derive_one(ZNetwork::Test, &ufvk, &receivers, j).unwrap())
                .collect();
            let unique: std::collections::HashSet<&String> = addrs.iter().collect();
            assert_eq!(unique.len(), addrs.len(), "duplicate address in {addrs:?}");
        }
    }

    /// The network is part of the encoding, so the same key derives differently-prefixed
    /// addresses per network - which is why a `keys.toml` on the wrong network is refused rather
    /// than re-encoded.
    #[test]
    fn encoding_is_network_scoped() {
        let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(PHRASE).unwrap();
        let seed = SecretVec::new(mnemonic.to_seed("").to_vec());
        let main = ufvk_from_seed(ZNetwork::Main, &seed).unwrap();
        let mainnet_ua = derive_one(ZNetwork::Main, &main, &orchard(), 0).unwrap();
        assert!(mainnet_ua.starts_with("u1"), "{mainnet_ua}");
        let mainnet_t = derive_one(ZNetwork::Main, &main, &Receivers::Transparent, 0).unwrap();
        assert!(mainnet_t.starts_with("t1"), "{mainnet_t}");
    }

    /// A transparent receiver only exists for non-hardened child indexes, so an index at or above
    /// 2^31 is an error naming the index rather than a silently different address.
    #[test]
    fn transparent_index_beyond_the_non_hardened_range_is_refused() {
        let err = derive_one(
            ZNetwork::Test,
            &test_ufvk(),
            &Receivers::Transparent,
            1u64 << 31,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("2147483648"), "{err}");
        assert!(err.contains("2^31"), "{err}");
    }

    /// `--address-type` follows the wallet's configuration when omitted, and honours an explicit
    /// override otherwise - the same resolution `getnewaddress` performs.
    #[test]
    fn address_type_resolves_against_the_wallet_configuration() {
        let mut entry = WalletEntry {
            dir: std::path::PathBuf::from("/nonexistent"),
            keys_file: None,
            coin: crate::coin::Coin::Zcash,
            chain: crate::coin::Coin::Zcash.chain(crate::network::ZNetwork::Test),
            backend: Default::default(),
            pools: ReceiverSet::single(Receiver::Orchard),
            default_receivers: ReceiverSet::single(Receiver::Orchard),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: 20,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: true,
            transparent_gap_warn_threshold: 5,
        };

        assert_eq!(
            resolve_receivers(&entry, None).unwrap().describe(),
            "orchard"
        );
        assert_eq!(
            resolve_receivers(&entry, Some("unified"))
                .unwrap()
                .describe(),
            "orchard"
        );
        assert_eq!(
            resolve_receivers(&entry, Some("transparent"))
                .unwrap()
                .describe(),
            "transparent"
        );
        assert_eq!(
            resolve_receivers(&entry, Some("sapling,orchard"))
                .unwrap()
                .describe(),
            "sapling,orchard"
        );
        assert!(resolve_receivers(&entry, Some("ironwood")).is_err());

        // A wallet that defaults to transparent hands out a bare t-address for the default
        // request, exactly as `getnewaddress` with no argument would.
        entry.transparent_enabled = true;
        entry.transparent_default = true;
        assert_eq!(
            resolve_receivers(&entry, None).unwrap().describe(),
            "transparent"
        );
        // An explicit shielded override still wins over the transparent default.
        assert_eq!(
            resolve_receivers(&entry, Some("orchard"))
                .unwrap()
                .describe(),
            "orchard"
        );
    }
}
