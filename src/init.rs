//! `zecd init`: create a new wallet (age identity + mnemonic + account), ported from
//! `zcash-devtool/src/commands/wallet/init.rs`.

use std::path::Path;
use std::time::Duration;

use age::secrecy::ExposeSecret as _;
use anyhow::{anyhow, bail, Context};
use bip0039::{Count, English, Mnemonic};
use secrecy::{SecretVec, Zeroize};
use tokio::io::AsyncWriteExt as _;

use zcash_client_backend::data_api::{AccountBirthday, WalletWrite};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::chain::ChainSource as _;
use crate::config::{AppConfig, InitArgs, WalletEntry};
use crate::lightwalletd;
use crate::wallet::open;
use crate::wallet::store::{Passphrase, WalletStore};

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
    let entry: WalletEntry = config.wallets.get(&args.wallet).cloned().unwrap_or(WalletEntry {
        dir: config.datadir.join(&args.wallet),
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
    std::fs::create_dir_all(&wallet_dir)?;

    let identity_path = config
        .keys
        .age_identity
        .clone()
        .unwrap_or_else(|| config.datadir.join("identity.txt"));
    // An encrypted wallet wraps its mnemonic with a passphrase (age scrypt) and needs no
    // identity file; an unencrypted wallet wraps it to the age identity for unattended unlock.
    let recipients = if args.encrypt {
        None
    } else {
        Some(ensure_identity(&identity_path).await?)
    };
    // Read the passphrase early (before any network I/O) so we fail fast on mismatch/empty.
    let passphrase = if args.encrypt {
        Some(read_encryption_passphrase()?)
    } else {
        None
    };

    // init is a one-shot interactive command; it uses only the first configured endpoint (no
    // failover) - the daemon's actor does the multi-server failover at runtime.
    let mut servers = lightwalletd::resolve_all(
        &config.lightwalletd.servers,
        network,
        config.lightwalletd.tls_roots,
        config.lightwalletd.force_tls,
        config.lightwalletd.proxy,
    )?;
    lightwalletd::apply_zebra_auth(&mut servers, &config.zebra.auth());
    let server = servers
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no upstream servers configured"))?;
    let mut client = server
        .connect_timeout(Duration::from_secs(config.lightwalletd.connect_timeout_secs))
        .await
        .with_context(|| format!("connecting to {}", server.describe()))?;

    let chain_tip: u32 = client
        .latest_block()
        .await?
        .height
        .try_into()
        .map_err(|_| anyhow!("chain tip height does not fit into u32"))?;

    let (mnemonic, recover_until) = if args.restore {
        eprintln!("Enter the mnemonic phrase to restore, then press Enter:");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let phrase = line.trim();
        (
            <Mnemonic<English>>::from_phrase(phrase)?,
            Some(BlockHeight::from(chain_tip)),
        )
    } else {
        (Mnemonic::generate(Count::Words24), None)
    };

    // A freshly-generated wallet can have no history, so its birthday defaults to just below
    // the tip. A *restored* wallet may hold notes from any point in its past; defaulting
    // anywhere near the tip would silently skip them (the funds exist on chain but are never
    // scanned), so without --birthday we scan from Sapling activation - the start of the
    // shielded-note era - trading sync time for never missing funds.
    let birthday_height = BlockHeight::from(args.birthday.unwrap_or_else(|| {
        if args.restore {
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
        let treestate = client.tree_state(BlockHeight::from_u32(prior_height)).await?;
        AccountBirthday::from_treestate(treestate, recover_until)
            .map_err(|_| anyhow!("failed to derive account birthday from tree state"))?
    };

    match (passphrase, &recipients) {
        (Some(passphrase), _) => WalletStore::init_with_passphrase(
            &wallet_dir,
            passphrase,
            &mnemonic,
            birthday.height(),
            network,
        )?,
        (None, Some(recipients)) => WalletStore::init_with_mnemonic(
            &wallet_dir,
            recipients.iter().map(|r| r.as_ref() as _),
            &mnemonic,
            birthday.height(),
            network,
        )?,
        (None, None) => unreachable!("non-encrypted init always builds identity recipients"),
    }

    let seed = {
        let mut s = mnemonic.to_seed("");
        let secret = SecretVec::new(s.to_vec());
        s.zeroize();
        secret
    };

    let mut db = open::init_dbs(network, &wallet_dir)?;
    db.create_account(&args.account_name, &seed, &birthday, None)?;

    eprintln!("Wallet '{}' initialized at {}", args.wallet, wallet_dir.display());
    if args.encrypt {
        eprintln!(
            "Wallet is passphrase-encrypted; it starts locked. Call walletpassphrase \"<pass>\" <timeout> to unlock for sending."
        );
    } else {
        eprintln!("age identity: {}", identity_path.display());
    }
    if !args.restore {
        eprintln!("\nIMPORTANT - record this mnemonic seed phrase and keep it safe:\n");
        println!("{}", mnemonic.phrase());
        eprintln!();
    }
    Ok(())
}

async fn ensure_identity(path: &Path) -> anyhow::Result<Vec<Box<dyn age::Recipient + Send>>> {
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        let recipients = age::IdentityFile::from_file(path.to_string_lossy().into_owned())?
            .to_recipients()?;
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
