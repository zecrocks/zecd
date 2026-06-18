//! `zecd init`: create a new wallet (age identity + mnemonic + account), ported from
//! `zcash-devtool/src/commands/wallet/init.rs`.

use std::path::Path;
use std::time::Duration;

use age::secrecy::ExposeSecret as _;
use anyhow::{anyhow, bail, Context};
use bip0039::{Count, English, Mnemonic};
use secrecy::{SecretVec, Zeroize};
use tokio::io::AsyncWriteExt as _;

use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, AccountPurpose, AccountSource, WalletRead, WalletWrite,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::backend;
use crate::chain::ChainSource as _;
use crate::config::{AppConfig, ExportUfvkArgs, InitArgs, WalletEntry};
use crate::wallet::open;
use crate::wallet::store::{KmsInfo, Passphrase, WalletStore};

/// Read the encryption passphrase for `init --encrypt`. Prefers the `ZECD_WALLET_PASSPHRASE`
/// environment variable (for non-interactive/automated init); otherwise prompts on stderr and
/// reads it twice from stdin to confirm. Only the trailing newline is stripped, so a passphrase
/// may contain surrounding spaces.
fn read_encryption_passphrase() -> anyhow::Result<Passphrase> {
    if let Some(p) = std::env::var_os("ZECD_WALLET_PASSPHRASE") {
        let s = p.to_string_lossy().into_owned();
        if s.is_empty() {
            bail!("ZECD_WALLET_PASSPHRASE is set but empty");
        }
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
    if p1.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(Passphrase::from(p1))
}

pub async fn run(config: &AppConfig, args: &InitArgs) -> anyhow::Result<()> {
    let entry: WalletEntry = config
        .wallets
        .get(&args.wallet)
        .cloned()
        .unwrap_or_else(|| WalletEntry {
            dir: config.datadir.join(&args.wallet),
            pools: config.pools.enabled.clone(),
            default_receivers: config.pools.default_receivers.clone(),
        });
    let wallet_dir = entry.dir;
    let network = config.network;

    if WalletStore::exists(&wallet_dir) {
        return Err(anyhow!(
            "wallet '{}' is already initialized at {}",
            args.wallet,
            wallet_dir.display()
        ));
    }

    // Watch-only init: parse the UFVK up front (before any directory or network I/O) so a
    // malformed key fails fast. `--ufvk` conflicts with `--restore`/`--encrypt` at the clap
    // level. A `Some` UFVK means this is a watch-only wallet; `None` means it will hold
    // spending keys.
    let ufvk = args
        .ufvk
        .as_deref()
        .map(|s| {
            UnifiedFullViewingKey::decode(&network, s.trim())
                .map_err(|e| anyhow!("invalid unified full viewing key: {e}"))
        })
        .transpose()?;

    // zecd permits at most one spending wallet (any number of watch-only UFVK wallets may be
    // added alongside it). When creating a spending wallet, refuse up front if another
    // configured wallet already holds spending keys - the same invariant the daemon enforces at
    // startup, surfaced here so the operator finds out at `init` time rather than at the next
    // boot. Watch-only inits (`--ufvk`) are exempt: any number are allowed. Done before any
    // directory or network I/O so it fails fast and leaves nothing behind.
    if ufvk.is_none() {
        if let Some(existing) = existing_spending_wallet(network, &config.wallets, &args.wallet) {
            return Err(anyhow!(
                "cannot create spending wallet '{}': wallet '{}' already holds spending keys, \
                 and zecd allows at most one spending wallet (any number of watch-only UFVK \
                 wallets may be added alongside it). Create this wallet watch-only with `--ufvk` \
                 (see `zecd export-ufvk`), or remove/convert the existing spending wallet.",
                args.wallet,
                existing
            ));
        }
    }

    std::fs::create_dir_all(&wallet_dir)?;

    let identity_path = config
        .keys
        .age_identity
        .clone()
        .unwrap_or_else(|| config.datadir.join("identity.txt"));
    // How the mnemonic is protected at rest. All settled *before* any network I/O so a bad
    // passphrase / missing identity / misconfigured KMS fails fast:
    // - view-only (imported UFVK): no mnemonic at all, so there is no at-rest secret;
    // - keystore: age-encrypt to a fresh x25519 identity and wrap that identity with the
    //   configured cloud KMS key (auto-unlocks at startup via IAM-gated Decrypt);
    // - encrypt: wrap with a passphrase (age scrypt) - starts locked, `walletpassphrase`;
    // - default: wrap to the age identity file for unattended unlock.
    enum AtRest {
        ViewOnly,
        Kms {
            keystore: crate::keystore::Keystore,
            identity: age::x25519::Identity,
            wrapped: Vec<u8>,
        },
        Passphrase(Passphrase),
        Identity(Vec<Box<dyn age::Recipient + Send>>),
    }
    let at_rest = if ufvk.is_some() {
        AtRest::ViewOnly
    } else if args.keystore {
        let keystore = config.keystore.required()?;
        let identity = age::x25519::Identity::generate();
        let ctx = crate::keystore::WrapContext {
            wallet: args.wallet.clone(),
            network: network.name().to_string(),
        };
        eprintln!(
            "Wrapping the wallet key with {} key {}",
            keystore.provider.name(),
            keystore.key
        );
        let identity_str = identity.to_string();
        let wrapped = keystore
            .wrap(identity_str.expose_secret().as_bytes(), &ctx)
            .await
            .context("wrapping the wallet key (the credentials must allow KMS Encrypt)")?;
        // Prove the same credentials can unlock before committing anything to disk - an
        // Encrypt-only policy would otherwise brick sending until IAM is fixed.
        let back = keystore
            .unwrap(&wrapped, &ctx)
            .await
            .context("verifying KMS unwrap (the credentials must also allow KMS Decrypt)")?;
        if secrecy::ExposeSecret::expose_secret(&back).as_slice()
            != identity_str.expose_secret().as_bytes()
        {
            bail!("KMS unwrap verification returned different bytes");
        }
        AtRest::Kms {
            keystore,
            identity,
            wrapped,
        }
    } else if args.encrypt {
        AtRest::Passphrase(read_encryption_passphrase()?)
    } else {
        AtRest::Identity(ensure_identity(&identity_path).await?)
    };

    // init is a one-shot interactive command; it uses only the first configured endpoint (no
    // failover) - the daemon's actor does the multi-server failover at runtime.
    let mut servers = backend::resolve_all(
        &config.backend.servers,
        network,
        config.backend.tls_roots,
        config.backend.force_tls,
        config.backend.proxy,
    )?;
    backend::apply_zebra_auth(&mut servers, &config.zebra.auth());
    let server = servers
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no upstream servers configured"))?;
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
    } else if args.restore {
        eprintln!("Enter the mnemonic phrase to restore, then press Enter:");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let phrase = line.trim();
        (
            Some(<Mnemonic<English>>::from_phrase(phrase)?),
            Some(BlockHeight::from(chain_tip)),
        )
    } else {
        (Some(Mnemonic::generate(Count::Words24)), None)
    };

    // A freshly-generated wallet can have no history, so its birthday defaults to just below
    // the tip. A *restored* wallet (or an imported viewing key) may hold notes from any point
    // in its past; defaulting anywhere near the tip would silently skip them (the funds exist
    // on chain but are never scanned), so without --birthday we scan from Sapling activation -
    // the start of the shielded-note era - trading sync time for never missing funds.
    let key_may_have_history = args.restore || ufvk.is_some();
    let birthday_height = BlockHeight::from(args.birthday.unwrap_or_else(|| {
        if key_may_have_history {
            let sapling = u32::from(
                network
                    .activation_height(NetworkUpgrade::Sapling)
                    .expect("Sapling activation height is known"),
            );
            eprintln!(
                "No --birthday given; scanning the restored wallet from Sapling activation \
                 (height {sapling}) so no notes are missed. Pass --birthday <height> (at or \
                 before the wallet's first transaction) to make the initial sync much faster."
            );
            sapling
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
    match &at_rest {
        AtRest::ViewOnly => WalletStore::init_view_only(&wallet_dir, birthday.height(), network)?,
        AtRest::Kms {
            keystore,
            identity,
            wrapped,
        } => WalletStore::init_with_kms(
            &wallet_dir,
            &identity.to_public(),
            &KmsInfo {
                provider: keystore.provider,
                key: keystore.key.clone(),
                wrapped_identity: wrapped.clone(),
                context_wallet: args.wallet.clone(),
            },
            require_mnemonic(),
            birthday.height(),
            network,
        )?,
        AtRest::Passphrase(passphrase) => WalletStore::init_with_passphrase(
            &wallet_dir,
            passphrase.clone(),
            require_mnemonic(),
            birthday.height(),
            network,
        )?,
        AtRest::Identity(recipients) => WalletStore::init_with_mnemonic(
            &wallet_dir,
            recipients.iter().map(|r| r.as_ref() as _),
            require_mnemonic(),
            birthday.height(),
            network,
        )?,
    }

    let mut db = open::init_dbs(network, &wallet_dir)?;
    match (&ufvk, &mnemonic) {
        (Some(ufvk), _) => {
            db.import_account_ufvk(
                &args.account_name,
                ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )?;
        }
        (None, Some(mnemonic)) => {
            let seed = {
                let mut s = mnemonic.to_seed("");
                let secret = SecretVec::new(s.to_vec());
                s.zeroize();
                secret
            };
            db.create_account(&args.account_name, &seed, &birthday, None)?;
        }
        (None, None) => unreachable!("init either imports a UFVK or has a mnemonic"),
    }

    eprintln!(
        "Wallet '{}' initialized at {}",
        args.wallet,
        wallet_dir.display()
    );
    match &at_rest {
        AtRest::ViewOnly => eprintln!(
            "Watch-only wallet (imported UFVK): balances, history, and addresses are \
             available; spending and wallet-encryption RPCs are disabled."
        ),
        AtRest::Kms { keystore, .. } => eprintln!(
            "Wallet key is wrapped by {} key {}; the daemon auto-unlocks it at startup via \
             the cloud credentials (no identity file, no passphrase).",
            keystore.provider.name(),
            keystore.key
        ),
        AtRest::Passphrase(_) => eprintln!(
            "Wallet is passphrase-encrypted; it starts locked. Call walletpassphrase \"<pass>\" <timeout> to unlock for sending."
        ),
        AtRest::Identity(_) => eprintln!("age identity: {}", identity_path.display()),
    }
    if let Some(mnemonic) = mnemonic.filter(|_| !args.restore) {
        eprintln!("\nIMPORTANT - record this mnemonic seed phrase and keep it safe:\n");
        println!("{}", mnemonic.phrase());
        eprintln!();
    }
    Ok(())
}

/// `zecd export-ufvk`: print the wallet's Unified Full Viewing Key to stdout, for setting up
/// a watch-only zecd elsewhere (`init --ufvk`). The UFVK is read from the wallet DB (where it
/// is stored for scanning anyway), so this works for locked and passphrase-encrypted wallets
/// alike and never touches spending material. Offline: no upstream connection is made.
pub fn export_ufvk(config: &AppConfig, args: &ExportUfvkArgs) -> anyhow::Result<()> {
    let entry: WalletEntry = config
        .wallets
        .get(&args.wallet)
        .cloned()
        .unwrap_or_else(|| WalletEntry {
            dir: config.datadir.join(&args.wallet),
            pools: config.pools.enabled.clone(),
            default_receivers: config.pools.default_receivers.clone(),
        });
    let wallet_dir = entry.dir;

    if !WalletStore::exists(&wallet_dir) {
        return Err(anyhow!(
            "wallet '{}' is not initialized at {}",
            args.wallet,
            wallet_dir.display()
        ));
    }
    // The UFVK encoding is network-scoped; refuse a network flag that contradicts the wallet
    // on disk rather than emit a key the watch-only side would reject.
    let st = WalletStore::read(&wallet_dir)?;
    if st.network != config.network {
        return Err(anyhow!(
            "wallet '{}' is a {} wallet, but the configuration selects {}",
            args.wallet,
            st.network.name(),
            config.network.name()
        ));
    }

    let db = open::open_read(config.network, &wallet_dir)?;
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

    eprintln!(
        "Unified Full Viewing Key for wallet '{}' (grants full VIEW access - balances and \
         all transaction history - but cannot spend):",
        args.wallet
    );
    println!("{}", ufvk.encode(&config.network));
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
        .filter(|(_, entry)| WalletStore::exists(&entry.dir))
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

    use std::collections::BTreeMap;

    use bip0039::{English, Mnemonic};
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;

    use crate::network;

    /// The Orchard-only pool set these tests use (pool config is irrelevant to them).
    fn orchard_pools() -> crate::pools::PoolSet {
        crate::pools::PoolSet::single(crate::pools::Pool::Orchard)
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

    /// Build a fully-initialized spending wallet (keys.toml with a seed + a seed-derived
    /// account) at `dir`, so both the `WalletStore::exists` gate and the DB account match a
    /// real `zecd init`.
    fn make_spending_wallet(dir: &Path) {
        let net = network::regtest();
        let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
        WalletStore::init_with_passphrase(
            dir,
            Passphrase::from("test-pass".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            net,
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
        WalletStore::init_view_only(dir, BlockHeight::from_u32(1), net)
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
                pools: orchard_pools(),
                default_receivers: orchard_pools(),
            },
        );
        wallets.insert(
            "w2".to_string(),
            WalletEntry {
                dir: w2_dir.path().to_path_buf(),
                pools: orchard_pools(),
                default_receivers: orchard_pools(),
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
                    pools: orchard_pools(),
                    default_receivers: orchard_pools(),
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
