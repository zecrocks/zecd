//! Per-wallet on-disk metadata (`keys.toml`): network, birthday height, and the
//! age-encrypted BIP-39 mnemonic. Ported from `zcash-devtool/src/config.rs`.
#![allow(dead_code)] // network/birthday are read during init/open paths

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use bip0039::{English, Mnemonic};
use secrecy::{ExposeSecret, SecretVec, Zeroize};
use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::network::ZNetwork;

const KEYS_FILE: &str = "keys.toml";

pub fn keys_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(KEYS_FILE)
}

/// Parsed `keys.toml`.
pub struct WalletStore {
    pub network: ZNetwork,
    pub birthday: BlockHeight,
    seed_ciphertext: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StoreEncoding {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
}

impl WalletStore {
    /// True if a `keys.toml` exists for this wallet directory.
    pub fn exists(wallet_dir: &Path) -> bool {
        keys_path(wallet_dir).exists()
    }

    /// Create a new `keys.toml` holding the age-encrypted mnemonic.
    pub fn init_with_mnemonic<'a>(
        wallet_dir: &Path,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
    ) -> anyhow::Result<()> {
        std::fs::create_dir_all(wallet_dir)?;
        let path = keys_path(wallet_dir);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| anyhow!("creating {}: {e}", path.display()))?;

        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_mnemonic(recipients, mnemonic)?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
        };
        let text = toml::to_string(&encoding).map_err(|_| anyhow!("serializing keys.toml"))?;
        file.write_all(text.as_bytes())?;
        Ok(())
    }

    pub fn read(wallet_dir: &Path) -> anyhow::Result<WalletStore> {
        let path = keys_path(wallet_dir);
        let mut text = String::new();
        std::fs::File::open(&path)
            .map_err(|e| anyhow!("opening {}: {e}", path.display()))?
            .read_to_string(&mut text)?;
        let encoding: StoreEncoding = toml::from_str(&text)?;

        let network = encoding
            .network
            .as_deref()
            .map(ZNetwork::parse)
            .transpose()?
            .unwrap_or(ZNetwork::Test);

        let birthday = encoding.birthday.map(BlockHeight::from).unwrap_or_else(|| {
            network
                .activation_height(NetworkUpgrade::Sapling)
                .expect("Sapling activation height is known")
        });

        Ok(WalletStore {
            network,
            birthday,
            seed_ciphertext: encoding.mnemonic,
        })
    }

    /// Decrypt the stored mnemonic and derive the BIP-39 seed.
    pub fn decrypt_seed<'a>(
        &self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> anyhow::Result<Option<SecretVec<u8>>> {
        self.seed_ciphertext
            .as_ref()
            .map(|ct| decrypt_seed(identities, ct))
            .transpose()
    }

    pub fn has_seed(&self) -> bool {
        self.seed_ciphertext.is_some()
    }
}

fn encrypt_mnemonic<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
    mnemonic: &Mnemonic,
) -> anyhow::Result<String> {
    let encryptor = age::Encryptor::with_recipients(recipients)?;
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(mnemonic.phrase().as_bytes())?;
    writer.finish().and_then(|armor| armor.finish())?;
    Ok(String::from_utf8(ciphertext).expect("armor is valid UTF-8"))
}

fn decrypt_mnemonic<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> anyhow::Result<SecretVec<u8>> {
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ciphertext.as_bytes()))?;
    let mut buf = vec![];
    // Take ownership of the buffer into a `SecretVec` before propagating any read error so
    // partially-read secret bytes are still zeroized (matches devtool's rationale).
    let ret = decryptor.decrypt(identities)?.read_to_end(&mut buf);
    let res = SecretVec::new(buf);
    ret?;
    Ok(res)
}

fn decrypt_seed<'a>(
    identities: impl Iterator<Item = &'a dyn age::Identity>,
    ciphertext: &str,
) -> anyhow::Result<SecretVec<u8>> {
    let mnemonic_bytes = decrypt_mnemonic(identities, ciphertext)?;
    let phrase = std::str::from_utf8(mnemonic_bytes.expose_secret())?;
    let mut seed = <Mnemonic<English>>::from_phrase(phrase)?.to_seed("");
    let secret = SecretVec::new(seed.to_vec());
    seed.zeroize();
    Ok(secret)
}
