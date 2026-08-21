//! `zecd init`: create a new wallet (age identity + mnemonic + account), ported from
//! `zcash-devtool/src/commands/wallet/init.rs`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use age::secrecy::ExposeSecret as _;
use anyhow::{anyhow, bail, Context};
use bip0039::{Count, English, Mnemonic};
use secrecy::{SecretVec, Zeroize};
use tokio::io::AsyncWriteExt as _;

use tracing::warn;
use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, AccountPurpose, AccountSource, WalletRead, WalletWrite,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::backend;
use crate::chain::ChainSource as _;
use crate::config::{AppConfig, WalletEntry};
#[cfg(feature = "cli")]
use crate::config::{ExportUfvkArgs, InitArgs, RescanArgs};
use crate::network::ZNetwork;
use crate::pools::{Receiver, ReceiverSet};
use crate::wallet::keys;
use crate::wallet::open;
use crate::wallet::store::{Passphrase, WalletStore};

/// The default account birthday when `--birthday` is omitted for a restore/import: the
/// activation height of the earliest *enabled* shielded pool, with a human label. An
/// Orchard-only wallet (the default) can hold no notes before NU5 (Orchard activation), so it
/// starts there - much faster than the old Sapling-activation default while never missing an
/// Orchard note. A Sapling-enabled wallet must start at Sapling activation, where it could
/// first hold notes.
fn restore_birthday_default(network: ZNetwork, pools: &ReceiverSet) -> (u32, &'static str) {
    let (upgrade, label) = if pools.contains(Receiver::Sapling) {
        (NetworkUpgrade::Sapling, "Sapling")
    } else {
        (NetworkUpgrade::Nu5, "Orchard (NU5)")
    };
    let height = u32::from(
        network
            .activation_height(upgrade)
            .expect("pool activation height is known"),
    );
    (height, label)
}

/// Minimum length (in characters) for a wallet-encryption passphrase.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Reject a too-short passphrase before it wraps the mnemonic.
#[cfg(any(feature = "cli", test))]
fn validate_passphrase(p: &str) -> anyhow::Result<()> {
    let n = p.chars().count();
    if n < MIN_PASSPHRASE_CHARS {
        bail!("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters (got {n})");
    }
    Ok(())
}

/// Read the encryption passphrase for `init --encrypt`. Prefers the `ZECD_WALLET_PASSPHRASE`
/// environment variable (for non-interactive/automated init); otherwise prompts on stderr and
/// reads it twice from stdin to confirm. Only the trailing newline is stripped, so a passphrase
/// may contain surrounding spaces.
#[cfg(feature = "cli")]
fn read_encryption_passphrase() -> anyhow::Result<Passphrase> {
    if let Some(p) = std::env::var_os("ZECD_WALLET_PASSPHRASE") {
        let s = p.to_string_lossy().into_owned();
        validate_passphrase(&s)?;
        return Ok(Passphrase::from(s));
    }
    let read_line = |prompt: &str| -> anyhow::Result<String> {
        eprintln!("{prompt}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    };
    let p1 = read_line("Enter a passphrase to encrypt the wallet:")?;
    let p2 = read_line("Confirm passphrase:")?;
    if p1 != p2 {
        bail!("passphrases do not match");
    }
    validate_passphrase(&p1)?;
    Ok(Passphrase::from(p1))
}

/// Read a mnemonic phrase from the non-interactive sources first - the `ZECD_MNEMONIC`
/// environment variable, then `file` - and otherwise print `prompt` on stderr and read one line
/// from stdin. Surrounding whitespace is trimmed. Shared by `init --restore` and
/// `derive-address --mnemonic` so both accept the same inputs in the same precedence.
#[cfg(feature = "cli")]
pub(crate) fn read_mnemonic_phrase(
    file: Option<&Path>,
    prompt: &str,
) -> anyhow::Result<Mnemonic<English>> {
    let phrase = if let Some(p) = std::env::var_os("ZECD_MNEMONIC") {
        p.to_string_lossy().trim().to_string()
    } else if let Some(path) = file {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading mnemonic file {}", path.display()))?
            .trim()
            .to_string()
    } else {
        eprintln!("{prompt}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        line.trim().to_string()
    };
    Ok(<Mnemonic<English>>::from_phrase(&phrase)?)
}

/// Resolve the [`WalletEntry`] for `wallet`: the configured `[wallets.<name>]` entry, or the
/// default layout (`<datadir>/<name>`, global pool settings) for a wallet the config doesn't
/// name - exactly the entry the daemon would build for it.
pub(crate) fn resolve_wallet_entry(config: &AppConfig, wallet: &str) -> WalletEntry {
    config
        .wallets
        .get(wallet)
        .cloned()
        .unwrap_or_else(|| WalletEntry {
            dir: config.datadir.join(wallet),
            keys_file: None,
            coin: crate::coin::Coin::Zcash,
            chain: crate::coin::Coin::Zcash.chain(config.network),
            backend: Default::default(),
            pools: config.pools.enabled.clone(),
            default_receivers: config.pools.default_receivers.clone(),
            transparent_enabled: config.pools.transparent_enabled,
            transparent_default: config.pools.transparent_default,
            transparent_gap_limit: config.pools.transparent_gap_limit,
            transparent_initial_scan: config.pools.transparent_initial_scan,
            transparent_allow_beyond_recovery_window: config
                .pools
                .transparent_allow_beyond_recovery_window,
            transparent_gap_warn_threshold: config.pools.transparent_gap_warn_threshold,
        })
}

/// The restore phrase for [`init_wallet`], with any interactive input deferred behind a
/// callback: the CLI reads the phrase from stdin only *after* the upstream connect and tip
/// fetch (that ordering is observable - a dead upstream fails before the prompt), so a caller
/// that wants the same behavior supplies `Deferred` and one with the phrase in hand supplies
/// `Phrase`. The same pattern as [`rescan_wallet`]'s `confirm` callback.
pub enum MnemonicInput {
    Phrase(Mnemonic<English>),
    Deferred(Box<dyn FnOnce() -> anyhow::Result<Mnemonic<English>> + Send>),
}

impl MnemonicInput {
    fn resolve(self) -> anyhow::Result<Mnemonic<English>> {
        match self {
            MnemonicInput::Phrase(m) => Ok(m),
            MnemonicInput::Deferred(f) => f(),
        }
    }
}

/// How a seed wallet's mnemonic is protected at rest (ignored for a watch-only init, which has
/// no at-rest secret). The passphrase variants mirror [`MnemonicInput`]: the CLI prompts for
/// the passphrase after the wallet database checks and before any network I/O, so `Deferred`
/// preserves that ordering; a programmatic `Passphrase` is used as given (the caller owns its
/// strength - the CLI's prompt path enforces [`MIN_PASSPHRASE_CHARS`]).
pub enum EncryptionInput {
    /// Wrap to the age identity file for unattended unlock (created if missing).
    AgeIdentity,
    Passphrase(Passphrase),
    DeferredPassphrase(Box<dyn FnOnce() -> anyhow::Result<Passphrase> + Send>),
}

/// How the new wallet gets its key material.
pub enum InitKey {
    /// A fresh 24-word mnemonic; the [`InitOutcome`] carries it for the operator to record.
    Generate,
    /// Recover an existing seed wallet; the recovery window extends to the current tip.
    Restore(MnemonicInput),
    /// A watch-only wallet from this encoded Unified Full Viewing Key.
    WatchOnly(String),
}

/// What to create - the library-facing form of the `zecd init` flags.
pub struct InitOptions {
    pub wallet: String,
    pub key: InitKey,
    pub encryption: EncryptionInput,
    /// Birthday height; defaults to near-tip for a fresh wallet and to the earliest enabled
    /// pool's activation for a restore/import (safe but slow - see the CLI's warning).
    pub birthday: Option<u32>,
}

/// What [`init_wallet`] created - everything the CLI prints, as data.
pub struct InitOutcome {
    pub wallet: String,
    pub wallet_dir: PathBuf,
    pub keys_path: PathBuf,
    pub network: ZNetwork,
    /// The account birthday actually recorded (derived from the anchoring tree state).
    pub birthday: u32,
    pub watch_only: bool,
    /// True when the wallet is passphrase-encrypted (starts locked).
    pub encrypted: bool,
    /// The age identity file protecting the seed, when [`EncryptionInput::AgeIdentity`] was
    /// used (created if it did not exist).
    pub identity_path: Option<PathBuf>,
    /// The freshly generated mnemonic, present only for [`InitKey::Generate`] - the phrase the
    /// operator must record. NB `bip0039::Mnemonic` does not zeroize on drop (the CLI prints
    /// this to stdout, the same exposure); drop it promptly. The derived seed inside
    /// [`init_wallet`] is a zeroize-on-drop `SecretVec` throughout.
    pub generated_mnemonic: Option<Mnemonic<English>>,
}

#[cfg(feature = "cli")]
pub async fn run(config: &AppConfig, args: &InitArgs) -> anyhow::Result<()> {
    // Map the flags onto the library options. The interactive inputs stay shell-side, behind
    // the deferred callbacks, so their prompts fire at the same points they always have.
    let key = if let Some(encoded) = &args.ufvk {
        InitKey::WatchOnly(encoded.clone())
    } else if args.restore {
        let file = args.mnemonic_file.clone();
        InitKey::Restore(MnemonicInput::Deferred(Box::new(move || {
            read_mnemonic_phrase(
                file.as_deref(),
                "Enter the mnemonic phrase to restore, then press Enter:",
            )
        })))
    } else {
        InitKey::Generate
    };
    let encryption = if args.encrypt {
        EncryptionInput::DeferredPassphrase(Box::new(read_encryption_passphrase))
    } else {
        EncryptionInput::AgeIdentity
    };

    let outcome = init_wallet(
        config,
        InitOptions {
            wallet: args.wallet.clone(),
            key,
            encryption,
            birthday: args.birthday,
        },
    )
    .await?;

    eprintln!(
        "Wallet '{}' initialized at {}",
        outcome.wallet,
        outcome.wallet_dir.display()
    );
    if outcome.watch_only {
        eprintln!(
            "Watch-only wallet (imported UFVK): balances, history, and addresses are \
             available; spending and wallet-encryption RPCs are disabled."
        );
    } else if outcome.encrypted {
        eprintln!(
            "Wallet is passphrase-encrypted; it starts locked. Call walletpassphrase \"<pass>\" <timeout> to unlock for sending."
        );
    } else if let Some(identity_path) = &outcome.identity_path {
        eprintln!("age identity: {}", identity_path.display());
    }
    if let Some(mnemonic) = &outcome.generated_mnemonic {
        eprintln!("\nIMPORTANT - record this mnemonic seed phrase and keep it safe:\n");
        println!("{}", mnemonic.phrase());
        eprintln!();
    }
    Ok(())
}

/// The library core of `zecd init`: create (or restore/import) a wallet and its account,
/// returning what was created instead of printing it. No stdout/stderr; the only interactive
/// I/O possible is whatever the caller put behind the `Deferred` inputs. Everything else is
/// unchanged from the CLI: the datadir lock is taken for the duration, a live upstream is
/// dialed once (the account anchors on the tree state at `birthday - 1`), and every refusal
/// fires before anything is written.
pub async fn init_wallet(config: &AppConfig, opts: InitOptions) -> anyhow::Result<InitOutcome> {
    let InitOptions {
        wallet,
        key,
        encryption,
        birthday: birthday_opt,
    } = opts;
    // Single-instance guard: take the exclusive datadir lock before creating any wallet, held
    // until `init` returns. This refuses an `init` against a datadir a running daemon (or another
    // `init`) already owns, rather than racing it. See `crate::lock`.
    let _datadir_lock = crate::lock::lock_datadir(&config.datadir)?;

    let entry = resolve_wallet_entry(config, &wallet);
    let keys_path = entry.keys_path();
    let enabled_pools = entry.pools.clone();
    // Create the account under the wallet's external transparent gap limit (only when transparent
    // is enabled), so init pre-generates the same receiving-address window the daemon scans.
    let init_gap_limit = entry
        .transparent_enabled
        .then_some(entry.transparent_gap_limit);
    let network = entry.zcash_network();
    let wallet_dir = entry.dir;

    if WalletStore::exists(&keys_path) {
        return Err(anyhow!(
            "wallet '{}' is already initialized ({} exists)",
            wallet,
            keys_path.display()
        ));
    }

    // Watch-only init: parse the UFVK up front (before any directory or network I/O) so a
    // malformed key fails fast (`--ufvk` conflicts with `--restore`/`--encrypt` at the clap
    // level; the enum makes the same shapes unrepresentable here). A `Some` UFVK means this is
    // a watch-only wallet; `None` means it will hold spending keys.
    let (ufvk, restore_input) = match key {
        InitKey::WatchOnly(encoded) => (
            Some(
                UnifiedFullViewingKey::decode(&network, encoded.trim())
                    .map_err(|e| anyhow!("invalid unified full viewing key: {e}"))?,
            ),
            None,
        ),
        InitKey::Restore(input) => (None, Some(input)),
        InitKey::Generate => (None, None),
    };
    let restore = restore_input.is_some();

    // zecd permits at most one spending wallet (any number of watch-only UFVK wallets may be
    // added alongside it). When creating a spending wallet, refuse up front if another
    // configured wallet already holds spending keys - the same invariant the daemon enforces at
    // startup, surfaced here so the operator finds out at `init` time rather than at the next
    // boot. Watch-only inits (`--ufvk`) are exempt: any number are allowed. Done before any
    // directory or network I/O so it fails fast and leaves nothing behind.
    if ufvk.is_none() {
        if let Some(existing) = existing_spending_wallet(network, &config.wallets, &wallet) {
            return Err(anyhow!(
                "cannot create spending wallet '{}': wallet '{}' already holds spending keys, \
                 and zecd allows at most one spending wallet (any number of watch-only \
                 UFVK wallets may be added alongside it). Create this wallet watch-only with \
                 `--ufvk` (see `zecd export-ufvk`), or remove/convert the existing spending \
                 wallet.",
                wallet,
                existing
            ));
        }
    }

    std::fs::create_dir_all(&wallet_dir)?;

    // Open (and migrate) the wallet database up front and refuse to initialize into one that
    // already holds an account. Without this, a pre-existing (planted or leftover) database
    // would gain the operator's account *alongside* its own, and the daemon selects the first
    // account, so receive addresses could derive from a key that is not the operator's. Done
    // before any interactive or network I/O so a refusal is fast and leaves no keys.toml
    // behind.
    let mut db = open::init_dbs_with_gap_limit(network, &wallet_dir, init_gap_limit)?;
    ensure_no_preexisting_account(&db, &wallet, &wallet_dir)?;

    let identity_path = config
        .keys
        .age_identity
        .clone()
        .unwrap_or_else(|| config.datadir.join("identity.txt"));
    // How the mnemonic is protected at rest. All settled *before* any network I/O so a bad
    // passphrase / missing identity fails fast:
    // - view-only (imported UFVK): no mnemonic at all, so there is no at-rest secret;
    // - encrypt: wrap with a passphrase (age scrypt) - starts locked, `walletpassphrase`;
    // - default: wrap to the age identity file for unattended unlock.
    enum AtRest {
        ViewOnly,
        Passphrase(Passphrase),
        Identity(Vec<Box<dyn age::Recipient + Send>>),
    }
    let at_rest = if ufvk.is_some() {
        AtRest::ViewOnly
    } else {
        match encryption {
            EncryptionInput::Passphrase(passphrase) => AtRest::Passphrase(passphrase),
            EncryptionInput::DeferredPassphrase(read) => AtRest::Passphrase(read()?),
            EncryptionInput::AgeIdentity => {
                AtRest::Identity(ensure_identity(&identity_path).await?)
            }
        }
    };

    // init is a one-shot interactive command that dials the configured upstream once.
    let mut server = backend::resolve(&config.backend.server, network)?;
    backend::apply_zebra_auth(&mut server, &config.zebra.auth());
    backend::apply_cleartext_policy(
        &mut server,
        crate::chain::zebra::CleartextPolicy {
            rfc1918_is_local: config.backend.rfc1918_is_local,
            allow_remote_cleartext: config.backend.allow_remote_cleartext,
        },
    );
    backend::apply_tls(&mut server, config.backend.tls_options());
    backend::apply_transparent_capability_override(
        &mut server,
        config.backend.assume_transparent_in_compact_blocks,
    );
    let mut client = server
        .connect_timeout(Duration::from_secs(config.backend.connect_timeout_secs))
        .await
        .with_context(|| format!("connecting to {}", server.describe()))?;

    let chain_tip: u32 = client
        .latest_block()
        .await?
        .height
        .try_into()
        .map_err(|_| anyhow!("chain tip height does not fit into u32"))?;

    let (mnemonic, recover_until) = if ufvk.is_some() {
        // A watch-only wallet has no mnemonic; the imported key may have history, so treat
        // it like a restore (recovery window up to the current tip).
        (None, Some(BlockHeight::from(chain_tip)))
    } else if let Some(input) = restore_input {
        (Some(input.resolve()?), Some(BlockHeight::from(chain_tip)))
    } else {
        (Some(Mnemonic::generate(Count::Words24)), None)
    };

    // A freshly-generated wallet can have no history, so its birthday defaults to just below
    // the tip. A *restored* wallet (or an imported viewing key) may hold notes from any point
    // in its past; defaulting anywhere near the tip would silently skip them (the funds exist
    // on chain but are never scanned), so without --birthday we scan from the earliest enabled
    // pool's activation (Orchard/NU5 for the Orchard-only default) - never missing a note, at
    // the cost of a long initial sync we warn about.
    let key_may_have_history = restore || ufvk.is_some();
    let birthday_height = BlockHeight::from(birthday_opt.unwrap_or_else(|| {
        if key_may_have_history {
            let (height, label) = restore_birthday_default(network, &enabled_pools);
            warn!(
                "no --birthday given; scanning from {label} activation (height {height}) - a \
                 full rescan that is slow on mainnet. Pass --birthday <height> at or before the \
                 wallet's first transaction to speed up the initial sync."
            );
            height
        } else {
            chain_tip.saturating_sub(100)
        }
    }));
    let birthday = {
        // Fetch the tree state for the block before the birthday (leaks birthday to server).
        // Never request below height 1: lightwalletd treats a BlockId height of 0 as
        // "unspecified" and rejects it ("must specify a block height or ID"), and there is no
        // pre-genesis tree state. This happens on short chains (e.g. a fresh regtest network
        // where `chain_tip - 100` underflows to 0). `AccountBirthday::from_treestate` then
        // derives the actual birthday from the returned tree state's height.
        let prior_height = u32::from(birthday_height).saturating_sub(1).max(1);
        let treestate = client
            .tree_state(BlockHeight::from_u32(prior_height))
            .await?;
        AccountBirthday::from_treestate(treestate, recover_until)
            .map_err(|_| anyhow!("failed to derive account birthday from tree state"))?
    };

    // Non-view-only models always have a mnemonic (the `AtRest` variant and `ufvk.is_none()`
    // agree by construction); `expect` documents that invariant.
    let require_mnemonic = || {
        mnemonic
            .as_ref()
            .expect("non-view-only init always has a mnemonic")
    };

    // The BIP-39 seed for a seed wallet (zeroized on drop). Derived once, used both to pin the
    // account's UFVK into keys.toml and to create the account itself.
    let seed = mnemonic.as_ref().map(|m| {
        let mut s = m.to_seed("");
        let secret = SecretVec::new(s.to_vec());
        s.zeroize();
        secret
    });

    // The account UFVK to pin into keys.toml: the imported key for a watch-only wallet, the
    // seed's ZIP-32 index-0 derivation otherwise (the account `create_account` builds on the
    // account-less database guaranteed above). Every startup verifies the database's account
    // against this pin, so a later database swap fails closed (see `wallet::binding`).
    let pinned_ufvk = match (&ufvk, &seed) {
        (Some(ufvk), _) => ufvk.encode(&network),
        (None, Some(seed)) => crate::wallet::binding::seed_ufvk_encoded(
            network,
            seed,
            zip32::AccountId::try_from(0u32).expect("0 is a valid account index"),
        )?,
        (None, None) => unreachable!("init either imports a UFVK or has a mnemonic"),
    };

    match &at_rest {
        AtRest::ViewOnly => {
            WalletStore::init_view_only(&keys_path, birthday.height(), network, &pinned_ufvk)?
        }
        AtRest::Passphrase(passphrase) => WalletStore::init_with_passphrase(
            &keys_path,
            passphrase.clone(),
            require_mnemonic(),
            birthday.height(),
            network,
            &pinned_ufvk,
        )?,
        AtRest::Identity(recipients) => WalletStore::init_with_mnemonic(
            &keys_path,
            recipients.iter().map(|r| r.as_ref() as _),
            require_mnemonic(),
            birthday.height(),
            network,
            &pinned_ufvk,
        )?,
    }

    // zecd surfaces a single account per wallet, so the account label is a fixed constant
    // (the name is stored by librustzcash but zecd never reads it back).
    let account_name = "primary";
    let account_id = match (&ufvk, &seed) {
        (Some(ufvk), _) => db
            .import_account_ufvk(
                account_name,
                ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )?
            .id(),
        (None, Some(seed)) => db.create_account(account_name, seed, &birthday, None)?.0,
        (None, None) => unreachable!("init either imports a UFVK or has a mnemonic"),
    };

    // Cross-check the pin against the account actually created. These agree by construction
    // (same key material, same derivation); if they ever diverge, e.g. a librustzcash bump
    // changes what `create_account` derives, failing here at init is loud and immediate,
    // where a divergence first hitting the startup verifier would brick every fresh wallet
    // one boot later.
    let created_ufvk = crate::wallet::binding::account_ufvk_encoded(network, &db, account_id)?;
    if created_ufvk != pinned_ufvk {
        bail!(
            "internal error: the created account's viewing key does not match the key derived \
             for the keys.toml pin; refusing to leave an inconsistent wallet. Please report \
             this bug."
        );
    }

    Ok(InitOutcome {
        wallet,
        wallet_dir,
        keys_path,
        network,
        birthday: u32::from(birthday.height()),
        watch_only: matches!(at_rest, AtRest::ViewOnly),
        encrypted: matches!(at_rest, AtRest::Passphrase(_)),
        identity_path: matches!(at_rest, AtRest::Identity(_)).then_some(identity_path),
        generated_mnemonic: mnemonic.filter(|_| !restore),
    })
}

/// `zecd export-ufvk`: print the wallet's Unified Full Viewing Key to stdout, for setting up
/// a watch-only zecd elsewhere (`init --ufvk`). The UFVK is read from the wallet DB (where it
/// is stored for scanning anyway), so this works for locked and passphrase-encrypted wallets
/// alike and never touches spending material. Offline: no upstream connection is made.
#[cfg(feature = "cli")]
pub fn export_ufvk(config: &AppConfig, args: &ExportUfvkArgs) -> anyhow::Result<()> {
    let encoded = export_ufvk_string(config, &args.wallet)?;
    eprintln!(
        "Unified Full Viewing Key for wallet '{}' (grants full VIEW access - balances and \
         all transaction history - but cannot spend):",
        args.wallet
    );
    println!("{encoded}");
    Ok(())
}

/// The encoded UFVK behind [`export_ufvk`] - the library core, which reads the wallet DB and
/// prints nothing. Works for locked and passphrase-encrypted wallets alike (the UFVK is stored
/// for scanning anyway) and never touches spending material.
pub fn export_ufvk_string(config: &AppConfig, wallet: &str) -> anyhow::Result<String> {
    let entry = resolve_wallet_entry(config, wallet);
    let keys_path = entry.keys_path();
    let network = entry.zcash_network();
    let wallet_dir = entry.dir;

    if !WalletStore::exists(&keys_path) {
        return Err(anyhow!(
            "wallet '{}' is not initialized ({} missing)",
            wallet,
            keys_path.display()
        ));
    }
    // The UFVK encoding is network-scoped; refuse a network flag that contradicts the wallet
    // on disk rather than emit a key the watch-only side would reject.
    let st = WalletStore::read(&keys_path)?;
    ensure_store_matches(&st, wallet, network)?;

    let db = open::open_read(network, &wallet_dir)?;
    let account_id = *db
        .get_account_ids()?
        .first()
        .ok_or_else(|| anyhow!("wallet has no accounts; run `init` first"))?;
    let account = db
        .get_account(account_id)?
        .ok_or_else(|| anyhow!("selected account not found"))?;
    let ufvk = account
        .ufvk()
        .ok_or_else(|| anyhow!("account has no unified full viewing key"))?;
    Ok(ufvk.encode(&network))
}

/// `zecd rescan`: the recovery path for a broken wallet database - e.g. a persistent
/// `PutBlocksCommitmentTree`/shardtree-conflict sync error that repeats at the same block range
/// across restarts and version upgrades (the daemon's sync-error log points here when it
/// detects that pattern). Deletes the wallet's *database* files while **keeping** `keys.toml`
/// (seed, network, birthday, UFVK pin), so the next daemon start takes the existing
/// empty-data-directory bootstrap path: it recreates the account from the seed and rescans the
/// chain from the wallet birthday, re-deriving all funds and history. This is safe by zecd's
/// statelessness invariant - everything in the database is rebuildable from seed + chain.
#[cfg(feature = "cli")]
pub fn rescan(config: &AppConfig, args: &RescanArgs) -> anyhow::Result<()> {
    // Same single-instance guard as `init`: refuses while the daemon (or another writer) owns
    // the datadir, so the database can't be deleted out from under a live wallet.
    let _datadir_lock = crate::lock::lock_datadir(&config.datadir)?;

    let entry = resolve_wallet_entry(config, &args.wallet);
    let removed = rescan_wallet(
        entry.zcash_network(),
        &args.wallet,
        &entry.keys_path(),
        &entry.dir,
        |st| {
            if args.yes {
                return Ok(true);
            }
            eprintln!(
                "This deletes the wallet database for '{}' at {} (keys.toml and the seed are \
                 kept).\nOn the next start zecd rebuilds the account from the seed and rescans \
                 from the wallet birthday ({}), which re-derives all funds and history but can \
                 take a while.\nType 'yes' to continue:",
                args.wallet,
                entry.dir.display(),
                u32::from(st.birthday)
            );
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim() == "yes")
        },
    )?;

    if removed.is_empty() {
        eprintln!(
            "Wallet '{}' has no database files at {}; nothing to delete. The next daemon start \
             will build it fresh from keys.toml.",
            args.wallet,
            entry.dir.display()
        );
    } else {
        eprintln!(
            "Wallet '{}' database removed ({}).",
            args.wallet,
            removed.join(", ")
        );
    }
    let st = WalletStore::read(&entry.keys_path())?;
    eprintln!(
        "Start zecd and it will rebuild the account from keys.toml and rescan from birthday {} \
         (requires [keys] bootstrap_from_keys, which is on by default).{}",
        u32::from(st.birthday),
        if st.is_encrypted() {
            "\nThis wallet is passphrase-encrypted: the rebuild starts at the first \
             `walletpassphrase` after the daemon is up."
        } else {
            ""
        }
    );
    Ok(())
}

/// The checks + deletion behind [`rescan`] - the library core, also unit-testable without an
/// [`AppConfig`] or stdin. `confirm` is consulted (with the parsed `keys.toml`) after
/// validation and before anything is deleted; returning `false` aborts cleanly. NB unlike
/// [`rescan`] this takes no datadir lock - a caller that owns a running node must not invoke
/// it on that node's datadir.
///
/// Refusals, in order: an uninitialized wallet (no `keys.toml` - deleting the database would
/// destroy the only record of the wallet), a network mismatch (the rebuilt scan would run on
/// the wrong chain), and a watch-only wallet (no seed to rebuild from - the daemon's bootstrap
/// path cannot recreate a view-only account, so the recovery there is a fresh
/// `init --ufvk`). Returns the database files/directories actually removed. Idempotent: an
/// already-wiped wallet succeeds with an empty list.
pub fn rescan_wallet(
    network: ZNetwork,
    wallet: &str,
    keys_path: &Path,
    wallet_dir: &Path,
    confirm: impl FnOnce(&WalletStore) -> anyhow::Result<bool>,
) -> anyhow::Result<Vec<String>> {
    if !WalletStore::exists(keys_path) {
        return Err(anyhow!(
            "wallet '{}' is not initialized ({} missing); there is no database to rebuild - \
             run `zecd init` to create a wallet",
            wallet,
            keys_path.display()
        ));
    }
    let st = WalletStore::read(keys_path)?;
    ensure_store_matches(&st, wallet, network)?;
    if !st.has_seed() {
        return Err(anyhow!(
            "wallet '{}' is watch-only (keys.toml holds no seed), so the daemon cannot rebuild \
             its account from keys.toml alone. Delete the wallet directory and recreate it with \
             `zecd init --wallet {} --ufvk <key> --birthday <height>` (export the key from the \
             spending wallet with `zecd export-ufvk`) instead.",
            wallet,
            wallet
        ));
    }
    if !confirm(&st)? {
        return Err(anyhow!("rescan aborted (expected 'yes')"));
    }

    // The wallet database and the compact-block cache (`open::init_dbs` recreates all of these
    // on the next start). `keys.toml` - which may live outside the wallet dir via `keys_file` -
    // and the datadir-level `identity.txt` are deliberately untouched.
    let mut removed = Vec::new();
    for file in [
        "data.sqlite",
        "data.sqlite-wal",
        "data.sqlite-shm",
        "blockmeta.sqlite",
        "blockmeta.sqlite-wal",
        "blockmeta.sqlite-shm",
    ] {
        let path = wallet_dir.join(file);
        match std::fs::remove_file(&path) {
            Ok(()) => removed.push(file.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow!("removing {}: {e}", path.display())),
        }
    }
    let blocks = wallet_dir.join("blocks");
    match std::fs::remove_dir_all(&blocks) {
        Ok(()) => removed.push("blocks/".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(anyhow!("removing {}: {e}", blocks.display())),
    }
    Ok(removed)
}

/// Refuse to initialize into a wallet database that already contains an account. `init` only
/// ever creates the account of a *fresh* database; a database that has one already was planted,
/// left over from a different wallet, or otherwise unexpected, and silently adding the
/// operator's account beside it would let the daemon later serve the pre-existing (first)
/// account's addresses. Fail loud and let the operator decide.
fn ensure_no_preexisting_account(
    db: &open::WriteDb,
    wallet: &str,
    wallet_dir: &Path,
) -> anyhow::Result<()> {
    let accounts = db.get_account_ids()?.len();
    if accounts == 0 {
        return Ok(());
    }
    Err(anyhow!(
        "wallet '{}' has no keys.toml, but its database at {} already contains {} account(s). \
         Refusing to initialize into an unexpected pre-existing database: it may belong to a \
         different wallet, and the daemon would serve its first account's addresses. Move the \
         existing data directory aside (or delete it, if it is not yours) and re-run `zecd \
         init`.",
        wallet,
        open::data_db_path(wallet_dir).display(),
        accounts
    ))
}

/// Refuse a `keys.toml` that belongs to a different network than the configuration selects,
/// rather than acting on it.
fn ensure_store_matches(
    store: &WalletStore,
    wallet: &str,
    network: ZNetwork,
) -> anyhow::Result<()> {
    if store.network != network {
        return Err(anyhow!(
            "wallet '{}' is a {} wallet, but the configuration selects {}",
            wallet,
            store.network.name(),
            network.name()
        ));
    }
    Ok(())
}

/// Scan the configured `wallets` (other than `exclude`) for one that is already initialized and
/// holds spending keys, returning its name. Used by the `init` guard so a second spending
/// wallet is refused before any work is done. The scope is `config.wallets` - exactly the set
/// the daemon would load - so the two guards agree.
fn existing_spending_wallet(
    network: crate::network::ZNetwork,
    wallets: &std::collections::BTreeMap<String, WalletEntry>,
    exclude: &str,
) -> Option<String> {
    wallets
        .iter()
        .filter(|(name, _)| name.as_str() != exclude)
        .filter(|(_, entry)| WalletStore::exists(&entry.keys_path()))
        .find(|(_, entry)| wallet_has_spending_keys(network, &entry.dir))
        .map(|(name, _)| name.clone())
}

/// Whether an initialized wallet at `wallet_dir` holds spending keys (i.e. its account is not a
/// watch-only UFVK import - the same `AccountSource::Imported { ViewOnly }` test the actor uses
/// for `watch_only`). Best-effort: a wallet whose DB can't be read or has no account is treated
/// as non-spending, so a single unreadable sibling never blocks `init` - the daemon's startup
/// guard is the backstop.
fn wallet_has_spending_keys(network: crate::network::ZNetwork, wallet_dir: &Path) -> bool {
    let Ok(db) = open::open_read(network, wallet_dir) else {
        return false;
    };
    let Ok(ids) = db.get_account_ids() else {
        return false;
    };
    let Some(id) = ids.first().copied() else {
        return false;
    };
    match db.get_account(id) {
        Ok(Some(account)) => !matches!(
            account.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::ViewOnly,
                ..
            }
        ),
        _ => false,
    }
}

async fn ensure_identity(path: &Path) -> anyhow::Result<Vec<Box<dyn age::Recipient + Send>>> {
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        // Re-use of an existing identity: refuse it if its permissions have since been widened
        // (the file is created 0600, but nothing prevents a later chmod) - mirrors the load-time
        // check on the daemon's auto-unlock path so init can't silently bless an exposed key.
        keys::check_identity_file_permissions(path)?;
        let recipients =
            age::IdentityFile::from_file(path.to_string_lossy().into_owned())?.to_recipients()?;
        return Ok(recipients);
    }

    eprintln!(
        "Generating a new age identity to encrypt the mnemonic at {}",
        path.display()
    );
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    // Create the identity file with mode 0600 set atomically at open time, rather than
    // creating under the umask and chmod-ing afterwards: the age secret key must never be
    // briefly world-readable between create and set_permissions. `create_new` preserves the
    // refusal to clobber an existing identity. Mirrors the cookie writer in `server::auth`.
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        // tokio's OpenOptions exposes `mode` as an inherent method (no trait import needed).
        opts.mode(0o600);
    }
    let mut f = opts.open(path).await?;
    f.write_all(b"# zecd age identity (KEEP SECRET)\n").await?;
    f.write_all(format!("# public key: {recipient}\n").as_bytes())
        .await?;
    f.write_all(format!("{}\n", identity.to_string().expose_secret()).as_bytes())
        .await?;
    f.flush().await?;

    Ok(vec![Box::new(recipient)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_birthday_default_is_pool_aware() {
        use crate::pools::{Receiver, ReceiverSet};
        // Orchard-only (the default): scan from NU5/Orchard activation - no Orchard note can
        // predate it.
        let (h, label) =
            restore_birthday_default(ZNetwork::Main, &ReceiverSet::single(Receiver::Orchard));
        assert!(label.contains("Orchard"), "{label}");
        assert_eq!(
            h,
            u32::from(
                ZNetwork::Main
                    .activation_height(NetworkUpgrade::Nu5)
                    .unwrap()
            )
        );
        // Sapling enabled: scan from the earlier Sapling activation, where a Sapling note could
        // first exist (defaulting to NU5 would silently skip pre-NU5 Sapling funds).
        let sap = ReceiverSet::parse(&["sapling".to_string(), "orchard".to_string()]).unwrap();
        let (hs, label_s) = restore_birthday_default(ZNetwork::Main, &sap);
        assert_eq!(label_s, "Sapling");
        assert_eq!(
            hs,
            u32::from(
                ZNetwork::Main
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap()
            )
        );
        assert!(hs < h, "Sapling activation precedes NU5");
    }

    #[test]
    fn passphrase_min_length_is_enforced() {
        // Too short (and empty) are rejected; exactly the minimum and longer pass.
        assert!(validate_passphrase("").is_err());
        assert!(validate_passphrase("short").is_err());
        assert!(validate_passphrase("eleven chrs").is_err()); // 11 chars
        assert!(validate_passphrase("twelve chars").is_ok()); // 12 chars
        assert!(validate_passphrase("a much longer passphrase").is_ok());
    }

    use std::collections::BTreeMap;

    use bip0039::{English, Mnemonic};
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;

    use crate::network;

    /// The Orchard-only pool set these tests use (pool config is irrelevant to them).
    fn orchard_pools() -> crate::pools::ReceiverSet {
        crate::pools::ReceiverSet::single(crate::pools::Receiver::Orchard)
    }

    /// The committed testnet test mnemonic (valueless), reused here purely as a deterministic
    /// seed source for throwaway regtest wallets.
    const TEST_PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    fn test_seed() -> SecretVec<u8> {
        let mut seed = <Mnemonic<English>>::from_phrase(TEST_PHRASE)
            .unwrap()
            .to_seed("");
        let secret = SecretVec::new(seed.to_vec());
        seed.zeroize();
        secret
    }

    fn genesis_birthday() -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
            None,
        )
    }

    /// The test seed's index-0 UFVK in its network-scoped encoding (what `init` pins).
    fn test_ufvk_encoded(net: crate::network::ZNetwork) -> String {
        crate::wallet::binding::seed_ufvk_encoded(
            net,
            &test_seed(),
            zip32::AccountId::try_from(0u32).unwrap(),
        )
        .expect("derive the test seed's UFVK")
    }

    /// Build a fully-initialized spending wallet (keys.toml with a seed + a seed-derived
    /// account) at `dir`, so both the `WalletStore::exists` gate and the DB account match a
    /// real `zecd init`.
    fn make_spending_wallet(dir: &Path) {
        let net = network::regtest();
        let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
        WalletStore::init_with_passphrase(
            &crate::wallet::store::keys_path(dir),
            Passphrase::from("test-pass".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            net,
            &test_ufvk_encoded(net),
        )
        .expect("write spending keys.toml");
        let mut db = open::init_dbs(net, dir).expect("init spending dbs");
        db.create_account("primary", &test_seed(), &genesis_birthday(), None)
            .expect("create spending account");
    }

    /// Build a fully-initialized watch-only wallet (seedless keys.toml + a ViewOnly UFVK
    /// import) at `dir`.
    fn make_watch_only_wallet(dir: &Path) {
        let net = network::regtest();
        WalletStore::init_view_only(
            &crate::wallet::store::keys_path(dir),
            BlockHeight::from_u32(1),
            net,
            &test_ufvk_encoded(net),
        )
        .expect("write watch-only keys.toml");
        let ufvk = {
            use secrecy::ExposeSecret as _;
            let seed = test_seed();
            UnifiedSpendingKey::from_seed(
                &net,
                seed.expose_secret(),
                zip32::AccountId::try_from(0u32).unwrap(),
            )
            .expect("derive USK")
            .to_unified_full_viewing_key()
        };
        let mut db = open::init_dbs(net, dir).expect("init watch-only dbs");
        db.import_account_ufvk(
            "watch",
            &ufvk,
            &genesis_birthday(),
            AccountPurpose::ViewOnly,
            None,
        )
        .expect("import the UFVK view-only");
    }

    /// The init-time data-directory guard: an account-bearing database refuses `init`, an
    /// empty (fresh) one passes. This is the check that keeps `zecd init` from absorbing a
    /// planted or leftover database's account as the wallet's own.
    #[test]
    fn init_refuses_a_database_that_already_has_an_account() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();

        // A fresh (migrated, account-less) database passes.
        let mut db = open::init_dbs(net, dir.path()).expect("init dbs");
        ensure_no_preexisting_account(&db, "default", dir.path())
            .expect("an empty database must not block init");

        // The same database with an account (planted, leftover, whatever) refuses.
        db.create_account("primary", &test_seed(), &genesis_birthday(), None)
            .expect("create account");
        let err = ensure_no_preexisting_account(&db, "default", dir.path())
            .expect_err("an account-bearing database must refuse init");
        assert!(
            err.to_string().contains("already contains 1 account"),
            "{err}"
        );
    }

    #[test]
    fn spending_keys_detected_for_seed_wallet_not_watch_only() {
        let net = network::regtest();
        let spend = tempfile::tempdir().unwrap();
        let watch = tempfile::tempdir().unwrap();
        let empty = tempfile::tempdir().unwrap();
        make_spending_wallet(spend.path());
        make_watch_only_wallet(watch.path());

        assert!(
            wallet_has_spending_keys(net, spend.path()),
            "a seed-derived wallet holds spending keys"
        );
        assert!(
            !wallet_has_spending_keys(net, watch.path()),
            "a view-only UFVK import does not hold spending keys"
        );
        // An uninitialized directory has no account, so it is treated as non-spending (the guard
        // is best-effort and never blocks on an unreadable sibling).
        assert!(
            !wallet_has_spending_keys(net, empty.path()),
            "an empty wallet dir is not a spending wallet"
        );
    }

    #[test]
    fn existing_spending_wallet_finds_the_other_spender() {
        let net = network::regtest();
        let default_dir = tempfile::tempdir().unwrap();
        let w2_dir = tempfile::tempdir().unwrap();
        make_spending_wallet(default_dir.path());

        let mut wallets = BTreeMap::new();
        wallets.insert(
            "default".to_string(),
            WalletEntry {
                dir: default_dir.path().to_path_buf(),
                keys_file: None,
                coin: crate::coin::Coin::Zcash,
                chain: crate::coin::Coin::Zcash.chain(net),
                backend: Default::default(),
                pools: orchard_pools(),
                default_receivers: orchard_pools(),
                transparent_enabled: false,
                transparent_default: false,
                transparent_gap_limit: 20,
                transparent_initial_scan: 0,
                transparent_allow_beyond_recovery_window: true,
                transparent_gap_warn_threshold: 5,
            },
        );
        wallets.insert(
            "w2".to_string(),
            WalletEntry {
                dir: w2_dir.path().to_path_buf(),
                keys_file: None,
                coin: crate::coin::Coin::Zcash,
                chain: crate::coin::Coin::Zcash.chain(net),
                backend: Default::default(),
                pools: orchard_pools(),
                default_receivers: orchard_pools(),
                transparent_enabled: false,
                transparent_default: false,
                transparent_gap_limit: 20,
                transparent_initial_scan: 0,
                transparent_allow_beyond_recovery_window: true,
                transparent_gap_warn_threshold: 5,
            },
        );

        // Creating spending wallet 'w2' must see the existing spending 'default'.
        assert_eq!(
            existing_spending_wallet(net, &wallets, "w2").as_deref(),
            Some("default"),
            "the existing spending wallet is detected"
        );
        // Re-initializing 'default' itself excludes it, so no conflict is reported.
        assert_eq!(
            existing_spending_wallet(net, &wallets, "default"),
            None,
            "the wallet being created is excluded from the scan"
        );
    }

    #[test]
    fn watch_only_siblings_do_not_count_as_spenders() {
        let net = network::regtest();
        let view_a = tempfile::tempdir().unwrap();
        let view_b = tempfile::tempdir().unwrap();
        let default_dir = tempfile::tempdir().unwrap();
        make_watch_only_wallet(view_a.path());
        make_watch_only_wallet(view_b.path());

        let mut wallets = BTreeMap::new();
        for (name, dir) in [
            ("default", &default_dir),
            ("view-a", &view_a),
            ("view-b", &view_b),
        ] {
            wallets.insert(
                name.to_string(),
                WalletEntry {
                    dir: dir.path().to_path_buf(),
                    keys_file: None,
                    coin: crate::coin::Coin::Zcash,
                    chain: crate::coin::Coin::Zcash.chain(net),
                    backend: Default::default(),
                    pools: orchard_pools(),
                    default_receivers: orchard_pools(),
                    transparent_enabled: false,
                    transparent_default: false,
                    transparent_gap_limit: 20,
                    transparent_initial_scan: 0,
                    transparent_allow_beyond_recovery_window: true,
                    transparent_gap_warn_threshold: 5,
                },
            );
        }

        // Creating the (first) spending 'default' alongside any number of watch-only wallets is
        // allowed: none of the existing siblings hold spending keys.
        assert_eq!(
            existing_spending_wallet(net, &wallets, "default"),
            None,
            "watch-only siblings never trip the single-spending-wallet guard"
        );
    }

    /// The `zecd rescan` core: on an initialized spending wallet it deletes exactly the
    /// database files (data.sqlite + the compact-block cache) and keeps `keys.toml` - the
    /// state the daemon's empty-datadir bootstrap path then rebuilds from - and it is
    /// idempotent (a second run finds nothing to delete and still succeeds).
    #[test]
    fn rescan_wipes_the_database_but_keeps_keys_toml() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();
        make_spending_wallet(dir.path());
        // The compact-block cache dir, as a running daemon would have left it.
        std::fs::create_dir_all(dir.path().join("blocks")).unwrap();
        std::fs::write(dir.path().join("blocks").join("100-aa-bb.compact"), b"x").unwrap();
        let keys_path = crate::wallet::store::keys_path(dir.path());
        assert!(open::data_db_path(dir.path()).exists());

        let removed = rescan_wallet(net, "default", &keys_path, dir.path(), |st| {
            // The confirmation sees the parsed store (the prompt shows its birthday).
            assert_eq!(u32::from(st.birthday), 1);
            Ok(true)
        })
        .expect("rescan an initialized spending wallet");
        assert!(removed.contains(&"data.sqlite".to_string()), "{removed:?}");
        assert!(removed.contains(&"blocks/".to_string()), "{removed:?}");
        assert!(!open::data_db_path(dir.path()).exists(), "database deleted");
        assert!(!dir.path().join("blocks").exists(), "block cache deleted");
        assert!(
            WalletStore::exists(&keys_path),
            "keys.toml (the rebuild source) must survive"
        );
        // Idempotent: nothing left to delete, still succeeds (recovery can be retried).
        let removed = rescan_wallet(net, "default", &keys_path, dir.path(), |_| Ok(true))
            .expect("re-running rescan is not an error");
        assert!(removed.is_empty(), "{removed:?}");

        // The daemon's bootstrap gate: an account-less database with keys.toml present is the
        // exact state `wallet::actor::spawn` rebuilds from.
        let db = open::init_dbs(net, dir.path()).expect("fresh dbs re-initialize");
        assert!(
            db.get_account_ids().expect("account ids").is_empty(),
            "the rebuilt database starts account-less (bootstrap recreates it from the seed)"
        );
    }

    /// `rescan`'s refusals: an uninitialized wallet (no keys.toml means no rebuild source), a
    /// watch-only wallet (no seed - the bootstrap path can't recreate a view-only account), a
    /// network mismatch, and a declined confirmation - each before anything is deleted.
    #[test]
    fn rescan_refuses_unrebuildable_wallets_and_declined_confirmation() {
        let net = network::regtest();

        // Uninitialized: no keys.toml.
        let empty = tempfile::tempdir().unwrap();
        let err = rescan_wallet(
            net,
            "default",
            &crate::wallet::store::keys_path(empty.path()),
            empty.path(),
            |_| Ok(true),
        )
        .expect_err("no keys.toml, nothing to rebuild from");
        assert!(err.to_string().contains("not initialized"), "{err}");

        // Watch-only: keys.toml holds no seed, so point at `init --ufvk` instead.
        let watch = tempfile::tempdir().unwrap();
        make_watch_only_wallet(watch.path());
        let watch_keys = crate::wallet::store::keys_path(watch.path());
        let err = rescan_wallet(net, "w", &watch_keys, watch.path(), |_| Ok(true))
            .expect_err("a watch-only wallet cannot be rebuilt from keys.toml");
        assert!(err.to_string().contains("watch-only"), "{err}");
        assert!(err.to_string().contains("--ufvk"), "{err}");
        assert!(
            open::data_db_path(watch.path()).exists(),
            "refusal must not delete anything"
        );

        // Network mismatch: the regtest wallet under a mainnet config would rescan the wrong
        // chain.
        let spend = tempfile::tempdir().unwrap();
        make_spending_wallet(spend.path());
        let spend_keys = crate::wallet::store::keys_path(spend.path());
        let err = rescan_wallet(ZNetwork::Main, "default", &spend_keys, spend.path(), |_| {
            Ok(true)
        })
        .expect_err("network mismatch is refused");
        assert!(err.to_string().contains("configuration selects"), "{err}");

        // Declined confirmation aborts before deletion.
        let err = rescan_wallet(net, "default", &spend_keys, spend.path(), |_| Ok(false))
            .expect_err("a declined confirmation aborts");
        assert!(err.to_string().contains("aborted"), "{err}");
        assert!(
            open::data_db_path(spend.path()).exists(),
            "nothing deleted on abort"
        );
    }

    /// The age identity holds the secret key that decrypts the mnemonic, so it must be created
    /// private. Asserts the end-state mode; atomicity (never world-readable mid-write) comes from
    /// creating with the mode set at open time rather than chmod-ing afterwards.
    #[cfg(unix)]
    #[tokio::test]
    async fn identity_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        ensure_identity(&path).await.expect("create identity");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "age identity must be private (0600)");
    }
}
