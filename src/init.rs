//! `zecd init`: create a new wallet (age identity + mnemonic + account), ported from
//! `zcash-devtool/src/commands/wallet/init.rs`.

use std::path::Path;

use age::secrecy::ExposeSecret as _;
use anyhow::{anyhow, Context};
use bip0039::{Count, English, Mnemonic};
use secrecy::{SecretVec, Zeroize};
use tokio::io::AsyncWriteExt as _;

use zcash_client_backend::data_api::{AccountBirthday, WalletWrite};
use zcash_client_backend::proto::service;
use zcash_protocol::consensus::BlockHeight;

use crate::config::{AppConfig, InitArgs, WalletEntry};
use crate::lightwalletd;
use crate::wallet::open;
use crate::wallet::store::WalletStore;

pub async fn run(config: &AppConfig, args: &InitArgs) -> anyhow::Result<()> {
    let entry: WalletEntry = config.wallets.get(&args.wallet).cloned().unwrap_or(WalletEntry {
        name: args.wallet.clone(),
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
    let recipients = ensure_identity(&identity_path).await?;

    let server = lightwalletd::resolve(
        &config.lightwalletd.server,
        network,
        config.lightwalletd.tls_roots,
        config.lightwalletd.force_tls,
    )?;
    let mut client = server
        .connect()
        .await
        .with_context(|| format!("connecting to lightwalletd {}", server.describe()))?;

    let chain_tip: u32 = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .into_inner()
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

    let birthday_height = BlockHeight::from(args.birthday.unwrap_or(chain_tip.saturating_sub(100)));
    let birthday = {
        // Fetch the tree state for the block before the birthday (leaks birthday to server).
        let request = service::BlockId {
            height: u64::from(birthday_height).saturating_sub(1),
            ..Default::default()
        };
        let treestate = client.get_tree_state(request).await?.into_inner();
        AccountBirthday::from_treestate(treestate, recover_until)
            .map_err(|_| anyhow!("failed to derive account birthday from tree state"))?
    };

    WalletStore::init_with_mnemonic(
        &wallet_dir,
        recipients.iter().map(|r| r.as_ref() as _),
        &mnemonic,
        birthday.height(),
        network,
    )?;

    let seed = {
        let mut s = mnemonic.to_seed("");
        let secret = SecretVec::new(s.to_vec());
        s.zeroize();
        secret
    };

    let mut db = open::init_dbs(network, &wallet_dir)?;
    db.create_account(&args.account_name, &seed, &birthday, None)?;

    eprintln!("Wallet '{}' initialized at {}", args.wallet, wallet_dir.display());
    eprintln!("age identity: {}", identity_path.display());
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
    let mut f = tokio::fs::File::create_new(path).await?;
    f.write_all(b"# zecd age identity (KEEP SECRET)\n").await?;
    f.write_all(format!("# public key: {recipient}\n").as_bytes())
        .await?;
    f.write_all(format!("{}\n", identity.to_string().expose_secret()).as_bytes())
        .await?;
    f.flush().await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(vec![Box::new(recipient)])
}
