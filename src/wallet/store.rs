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

/// A wallet passphrase, in `age`'s own `secrecy` version (the scrypt recipient/identity APIs
/// take this exact type - distinct from the crate-wide `secrecy = 0.8` used elsewhere).
pub type Passphrase = age::secrecy::SecretString;

const KEYS_FILE: &str = "keys.toml";

/// `keys.toml` `encryption` marker value: the mnemonic is wrapped with a passphrase (age
/// scrypt). Absent (or any other value) means the legacy identity-file model (no passphrase).
const ENC_PASSPHRASE: &str = "passphrase";

pub fn keys_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(KEYS_FILE)
}

/// Parsed `keys.toml`.
pub struct WalletStore {
    pub network: ZNetwork,
    pub birthday: BlockHeight,
    seed_ciphertext: Option<String>,
    /// True when the mnemonic is passphrase-encrypted (age scrypt) rather than wrapped to the
    /// age identity file. This is zecd's analog of Bitcoin Core's `HasEncryptionKeys()`.
    encrypted: bool,
}

#[derive(Deserialize, Serialize)]
struct StoreEncoding {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
    /// `"passphrase"` when the mnemonic is scrypt/passphrase-encrypted; omitted for the
    /// legacy identity-file model so existing `keys.toml` files round-trip unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
}

impl WalletStore {
    /// True if a `keys.toml` exists for this wallet directory.
    pub fn exists(wallet_dir: &Path) -> bool {
        keys_path(wallet_dir).exists()
    }

    /// Create a new `keys.toml` holding the mnemonic encrypted to the age identity (no
    /// passphrase - the legacy/unencrypted model, decryptable via the identity file).
    pub fn init_with_mnemonic<'a>(
        wallet_dir: &Path,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_mnemonic(recipients, mnemonic)?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: None,
        };
        write_keys_atomic(wallet_dir, &encoding, true)
    }

    /// Create a new `keys.toml` with the mnemonic passphrase-encrypted (age scrypt) - the
    /// Bitcoin-Core-style encrypted wallet, requiring `walletpassphrase` before spending.
    pub fn init_with_passphrase(
        wallet_dir: &Path,
        passphrase: Passphrase,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_phrase_with_passphrase(passphrase, mnemonic.phrase())?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: Some(ENC_PASSPHRASE.to_string()),
        };
        write_keys_atomic(wallet_dir, &encoding, true)
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

        let encrypted = encoding.encryption.as_deref() == Some(ENC_PASSPHRASE);

        Ok(WalletStore {
            network,
            birthday,
            seed_ciphertext: encoding.mnemonic,
            encrypted,
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

    /// Decrypt the stored mnemonic to its raw UTF-8 bytes (the phrase), without deriving the
    /// seed - used when re-wrapping the mnemonic under a new key (encrypt/change-passphrase).
    pub fn decrypt_mnemonic<'a>(
        &self,
        identities: impl Iterator<Item = &'a dyn age::Identity>,
    ) -> anyhow::Result<Option<SecretVec<u8>>> {
        self.seed_ciphertext
            .as_ref()
            .map(|ct| decrypt_mnemonic(identities, ct))
            .transpose()
    }

    /// Derive the BIP-39 seed from a passphrase-encrypted (age scrypt) mnemonic. A wrong
    /// passphrase surfaces as an `Err` (age `DecryptError`); the caller maps that to -14.
    pub fn decrypt_seed_with_passphrase(
        &self,
        passphrase: Passphrase,
    ) -> anyhow::Result<Option<SecretVec<u8>>> {
        self.seed_ciphertext
            .as_ref()
            .map(|ct| {
                let id = age::scrypt::Identity::new(passphrase);
                decrypt_seed(std::iter::once(&id as &dyn age::Identity), ct)
            })
            .transpose()
    }

    /// Decrypt a passphrase-encrypted mnemonic to its raw phrase bytes (for change-passphrase).
    pub fn decrypt_mnemonic_with_passphrase(
        &self,
        passphrase: Passphrase,
    ) -> anyhow::Result<Option<SecretVec<u8>>> {
        self.seed_ciphertext
            .as_ref()
            .map(|ct| {
                let id = age::scrypt::Identity::new(passphrase);
                decrypt_mnemonic(std::iter::once(&id as &dyn age::Identity), ct)
            })
            .transpose()
    }

    /// Atomically re-wrap the mnemonic `phrase` under `passphrase` (age scrypt) and rewrite
    /// `keys.toml` with the `encryption = "passphrase"` marker, preserving network/birthday.
    /// Used by `encryptwallet` and `walletpassphrasechange`.
    pub fn rewrite_with_passphrase(
        &self,
        wallet_dir: &Path,
        passphrase: Passphrase,
        phrase: &str,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_phrase_with_passphrase(passphrase, phrase)?),
            network: Some(self.network.name().to_string()),
            birthday: Some(u32::from(self.birthday)),
            encryption: Some(ENC_PASSPHRASE.to_string()),
        };
        write_keys_atomic(wallet_dir, &encoding, false)
    }

    pub fn has_seed(&self) -> bool {
        self.seed_ciphertext.is_some()
    }

    /// Whether the mnemonic is passphrase-encrypted (Bitcoin Core's `HasEncryptionKeys()`).
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}

/// Serialize `encoding` to `keys.toml`. `create_new` writes a fresh file (fails if it exists);
/// otherwise the file is replaced atomically (temp + rename) so a crash mid-rewrite can't leave
/// a truncated mnemonic. The file is created mode 0600 on Unix.
fn write_keys_atomic(
    wallet_dir: &Path,
    encoding: &StoreEncoding,
    create_new: bool,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(wallet_dir)?;
    let path = keys_path(wallet_dir);
    let text = toml::to_string(encoding).map_err(|_| anyhow!("serializing keys.toml"))?;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    if create_new {
        let mut file = opts
            .open(&path)
            .map_err(|e| anyhow!("creating {}: {e}", path.display()))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    } else {
        let tmp = path.with_extension("toml.tmp");
        {
            let mut file = opts
                .open(&tmp)
                .map_err(|e| anyhow!("creating {}: {e}", tmp.display()))?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| anyhow!("replacing {}: {e}", path.display()))?;
    }
    Ok(())
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

/// Encrypt a mnemonic phrase to a passphrase (age scrypt), armored - mirrors
/// [`encrypt_mnemonic`] but for the passphrase-encrypted wallet model.
fn encrypt_phrase_with_passphrase(passphrase: Passphrase, phrase: &str) -> anyhow::Result<String> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        age::armor::Format::AsciiArmor,
    )?)?;
    writer.write_all(phrase.as_bytes())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // The committed testnet test mnemonic (valueless), reused here only as a deterministic seed
    // source for the encryption round-trip.
    const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    #[test]
    fn passphrase_wallet_roundtrips_and_marks_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        WalletStore::init_with_passphrase(
            dir.path(),
            Passphrase::from("correct horse battery".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            ZNetwork::Test,
        )
        .unwrap();

        let st = WalletStore::read(dir.path()).unwrap();
        assert!(st.is_encrypted(), "a passphrase wallet must report as encrypted");
        assert!(st.has_seed());

        // The correct passphrase recovers the BIP-39 seed.
        let seed = st
            .decrypt_seed_with_passphrase(Passphrase::from("correct horse battery".to_string()))
            .unwrap()
            .unwrap();
        let expected = <Mnemonic<English>>::from_phrase(PHRASE).unwrap().to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);

        // A wrong passphrase fails (the actor maps this to RPC -14).
        assert!(st
            .decrypt_seed_with_passphrase(Passphrase::from("wrong".to_string()))
            .is_err());
    }

    #[test]
    fn identity_wallet_is_not_marked_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        WalletStore::init_with_mnemonic(
            dir.path(),
            std::iter::once(&recipient as &dyn age::Recipient),
            &mnemonic,
            BlockHeight::from_u32(1),
            ZNetwork::Test,
        )
        .unwrap();
        let st = WalletStore::read(dir.path()).unwrap();
        assert!(!st.is_encrypted());
        assert!(st.has_seed());
    }
}
