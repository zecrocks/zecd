//! `zecd rewrap`: re-wrap an existing wallet's mnemonic under the configured `[keystore]`
//! cloud KMS key, then exit. This is both the migration path onto a cloud keystore (from
//! the identity-file or passphrase models) and the KMS key-rotation tool (from an older
//! KMS key to the newly configured one). Offline: only the KMS endpoint is contacted -
//! no chain access, and the wallet DB is untouched (only `keys.toml` is atomically
//! rewritten).

use age::secrecy::ExposeSecret as _;
use anyhow::{anyhow, bail, Context};

use crate::config::{AppConfig, RewrapArgs, WalletEntry};
use crate::keystore::WrapContext;
use crate::wallet::keys;
use crate::wallet::store::{KmsInfo, Passphrase, WalletStore};

/// Read the current passphrase of an encrypted wallet: `ZECD_WALLET_PASSPHRASE`, else one
/// stdin prompt (no confirmation - we're decrypting, not setting).
fn read_current_passphrase() -> anyhow::Result<Passphrase> {
    if let Some(p) = std::env::var_os("ZECD_WALLET_PASSPHRASE") {
        let s = p.to_string_lossy().into_owned();
        if s.is_empty() {
            bail!("ZECD_WALLET_PASSPHRASE is set but empty");
        }
        return Ok(Passphrase::from(s));
    }
    eprintln!("Enter the wallet passphrase:");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(Passphrase::from(
        line.trim_end_matches(['\n', '\r']).to_string(),
    ))
}

pub async fn run(config: &AppConfig, args: &RewrapArgs) -> anyhow::Result<()> {
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

    let st = WalletStore::read(&wallet_dir).with_context(|| {
        format!(
            "wallet '{}' is not initialized at {}",
            args.wallet,
            wallet_dir.display()
        )
    })?;
    let keystore = config.keystore.required()?;

    // Decrypt the mnemonic with whatever wraps it today.
    let was_identity_wallet = !st.is_encrypted() && st.kms().is_none();
    let mnemonic = if st.is_encrypted() {
        let passphrase = read_current_passphrase()?;
        st.decrypt_mnemonic_with_passphrase(passphrase)
            .map_err(|_| anyhow!("the wallet passphrase is incorrect"))?
    } else if st.kms().is_some() {
        // Key rotation: unwrap with the old key recorded in keys.toml, re-wrap below with
        // the newly configured one.
        keys::decrypt_mnemonic_with_keystore(&st, config.keystore.endpoint.as_deref()).await?
    } else {
        let identity_path = config
            .keys
            .age_identity
            .clone()
            .unwrap_or_else(|| config.datadir.join("identity.txt"));
        keys::decrypt_mnemonic_with_identity(&st, &identity_path)
            .with_context(|| format!("decrypting the mnemonic with {}", identity_path.display()))?
    }
    .ok_or_else(|| anyhow!("wallet has no stored mnemonic"))?;
    let phrase = std::str::from_utf8(secrecy::ExposeSecret::expose_secret(&mnemonic).as_slice())
        .map_err(|_| anyhow!("stored mnemonic is not valid UTF-8"))?;

    // Wrap a fresh identity and prove the credentials can unwrap it (an Encrypt-only IAM
    // policy would otherwise brick sending) before rewriting keys.toml.
    let identity = age::x25519::Identity::generate();
    let ctx = WrapContext {
        wallet: args.wallet.clone(),
        network: st.network.name().to_string(),
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
    let back = keystore
        .unwrap(&wrapped, &ctx)
        .await
        .context("verifying KMS unwrap (the credentials must also allow KMS Decrypt)")?;
    if secrecy::ExposeSecret::expose_secret(&back).as_slice()
        != identity_str.expose_secret().as_bytes()
    {
        bail!("KMS unwrap verification returned different bytes");
    }

    let info = KmsInfo {
        provider: keystore.provider,
        key: keystore.key.clone(),
        wrapped_identity: wrapped,
        context_wallet: args.wallet.clone(),
    };
    st.rewrite_with_kms(&wallet_dir, &identity.to_public(), &info, phrase)?;

    eprintln!(
        "Wallet '{}' is now wrapped by {} key {}; the daemon auto-unlocks it at startup via \
         the cloud credentials.",
        args.wallet,
        keystore.provider.name(),
        keystore.key
    );
    if was_identity_wallet {
        eprintln!(
            "The age identity file is no longer needed for this wallet (other wallets may \
             still use it - it was not deleted)."
        );
    }
    Ok(())
}
