//! Per-wallet on-disk metadata (`keys.toml`): network, birthday height, and the
//! age-encrypted BIP-39 mnemonic. Ported from `zcash-devtool/src/config.rs`.

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
    /// The account's pinned Unified Full Viewing Key (network-scoped encoding). `init` records
    /// it and the daemon verifies the wallet database's account against it at every startup
    /// (see `wallet::binding`), so a replaced `data.sqlite` fails closed instead of silently
    /// diverting deposits to a foreign account. `None` only for a `keys.toml` written before
    /// this field existed; the daemon backfills it trust-on-first-use.
    pinned_ufvk: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StoreEncoding {
    mnemonic: Option<String>,
    network: Option<String>,
    birthday: Option<u32>,
    /// `"passphrase"` when the mnemonic is scrypt/passphrase-encrypted; omitted for the legacy
    /// identity-file model so existing `keys.toml` files round-trip unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<String>,
    /// The account's UFVK pin (see [`WalletStore::pinned_ufvk`]). Skipped when absent so a
    /// pre-pin `keys.toml` round-trips unchanged until the daemon backfills it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ufvk: Option<String>,
}

impl WalletStore {
    /// True if a `keys.toml` exists at this path.
    pub fn exists(keys_path: &Path) -> bool {
        keys_path.exists()
    }

    /// Create a new `keys.toml` holding the mnemonic encrypted to the age identity (no
    /// passphrase - the legacy/unencrypted model, decryptable via the identity file).
    /// `ufvk` is the account's pinned viewing key (see [`WalletStore::pinned_ufvk`]).
    pub fn init_with_mnemonic<'a>(
        keys_path: &Path,
        recipients: impl Iterator<Item = &'a dyn age::Recipient>,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
        ufvk: &str,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_mnemonic(recipients, mnemonic)?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: None,
            ufvk: Some(ufvk.to_string()),
        };
        write_keys_atomic(keys_path, &encoding, true)
    }

    /// Create a new `keys.toml` with the mnemonic passphrase-encrypted (age scrypt) - the
    /// Bitcoin-Core-style encrypted wallet, requiring `walletpassphrase` before spending.
    /// `ufvk` is the account's pinned viewing key (see [`WalletStore::pinned_ufvk`]).
    pub fn init_with_passphrase(
        keys_path: &Path,
        passphrase: Passphrase,
        mnemonic: &Mnemonic,
        birthday: BlockHeight,
        network: ZNetwork,
        ufvk: &str,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: Some(encrypt_phrase_with_passphrase(
                passphrase,
                mnemonic.phrase(),
            )?),
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: Some(ENC_PASSPHRASE.to_string()),
            ufvk: Some(ufvk.to_string()),
        };
        write_keys_atomic(keys_path, &encoding, true)
    }

    /// Create a new `keys.toml` for a watch-only wallet (imported UFVK): network, birthday,
    /// and the pinned viewing key, no mnemonic. The UFVK also lives (in the clear, as for
    /// every wallet) in the wallet DB's accounts table; the copy pinned here is what startup
    /// verifies that database account against. There is no spending material on disk at all.
    pub fn init_view_only(
        keys_path: &Path,
        birthday: BlockHeight,
        network: ZNetwork,
        ufvk: &str,
    ) -> anyhow::Result<()> {
        let encoding = StoreEncoding {
            mnemonic: None,
            network: Some(network.name().to_string()),
            birthday: Some(u32::from(birthday)),
            encryption: None,
            ufvk: Some(ufvk.to_string()),
        };
        write_keys_atomic(keys_path, &encoding, true)
    }

    /// Record `ufvk` as the wallet's pinned viewing key, rewriting `keys.toml` atomically and
    /// preserving every other field (the mnemonic ciphertext above all). A no-op when the file
    /// already pins exactly this value. Used to backfill the pin on a `keys.toml` from before
    /// the field existed; `init` writes the pin directly.
    pub fn pin_ufvk(keys_path: &Path, ufvk: &str) -> anyhow::Result<()> {
        let mut text = String::new();
        std::fs::File::open(keys_path)
            .map_err(|e| anyhow!("opening {}: {e}", keys_path.display()))?
            .read_to_string(&mut text)?;
        let mut encoding: StoreEncoding = toml::from_str(&text)?;
        if encoding.ufvk.as_deref() == Some(ufvk) {
            return Ok(());
        }
        encoding.ufvk = Some(ufvk.to_string());
        write_keys_atomic(keys_path, &encoding, false)
    }

    pub fn read(keys_path: &Path) -> anyhow::Result<WalletStore> {
        let path = keys_path;
        let mut text = String::new();
        std::fs::File::open(path)
            .map_err(|e| anyhow!("opening {}: {e}", path.display()))?
            .read_to_string(&mut text)?;
        let encoding: StoreEncoding = toml::from_str(&text)?;

        let network = encoding
            .network
            .as_deref()
            .map(ZNetwork::parse)
            .transpose()?
            .unwrap_or(ZNetwork::Test);

        // `init` always records a birthday; this fallback only fires for a hand-edited
        // `keys.toml` missing the field. Default to Orchard activation (NU5) - an Orchard-only
        // wallet (zecd's default) can hold no notes before it - rather than the older, slower
        // Sapling-activation default. (Pool-aware resolution lives in `init`, which knows the
        // wallet's enabled pools; this layer does not.)
        let birthday = encoding.birthday.map(BlockHeight::from).unwrap_or_else(|| {
            network
                .activation_height(NetworkUpgrade::Nu5)
                .expect("NU5 activation height is known")
        });

        let encrypted = encoding.encryption.as_deref() == Some(ENC_PASSPHRASE);

        Ok(WalletStore {
            network,
            birthday,
            seed_ciphertext: encoding.mnemonic,
            encrypted,
            pinned_ufvk: encoding.ufvk,
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

    pub fn has_seed(&self) -> bool {
        self.seed_ciphertext.is_some()
    }

    /// Whether the mnemonic is passphrase-encrypted (Bitcoin Core's `HasEncryptionKeys()`).
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The pinned account UFVK, if this `keys.toml` carries one (see the field docs).
    pub fn pinned_ufvk(&self) -> Option<&str> {
        self.pinned_ufvk.as_deref()
    }

    /// Test-only: remove the `ufvk` pin from an existing `keys.toml`, simulating a file
    /// written before the pin existed (the backfill/upgrade path under test).
    #[cfg(test)]
    pub fn strip_pin_for_tests(keys_path: &Path) {
        let text = std::fs::read_to_string(keys_path).unwrap();
        let mut encoding: StoreEncoding = toml::from_str(&text).unwrap();
        encoding.ufvk = None;
        write_keys_atomic(keys_path, &encoding, false).unwrap();
    }
}

/// Serialize `encoding` to `keys.toml`. `create_new` writes a fresh file (fails if it exists);
/// otherwise the file is replaced atomically (temp + rename) so a crash mid-rewrite can't leave
/// a truncated mnemonic. The file is created mode 0600 on Unix.
fn write_keys_atomic(
    path: &Path,
    encoding: &StoreEncoding,
    create_new: bool,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
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
            .open(path)
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
        std::fs::rename(&tmp, path).map_err(|e| anyhow!("replacing {}: {e}", path.display()))?;
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

    /// A stand-in pinned UFVK. The store layer treats the pin as an opaque string (derivation
    /// and verification live in `wallet::binding`), so any marker value exercises it.
    const UFVK: &str = "uviewtest1storeplaceholder";

    #[test]
    fn passphrase_wallet_roundtrips_and_marks_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let kp = keys_path(dir.path());
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        WalletStore::init_with_passphrase(
            &kp,
            Passphrase::from("correct horse battery".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            ZNetwork::Test,
            UFVK,
        )
        .unwrap();

        let st = WalletStore::read(&kp).unwrap();
        assert_eq!(st.pinned_ufvk(), Some(UFVK), "init records the pin");
        assert!(
            st.is_encrypted(),
            "a passphrase wallet must report as encrypted"
        );
        assert!(st.has_seed());

        // The correct passphrase recovers the BIP-39 seed.
        let seed = st
            .decrypt_seed_with_passphrase(Passphrase::from("correct horse battery".to_string()))
            .unwrap()
            .unwrap();
        let expected = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);

        // A wrong passphrase fails (the actor maps this to RPC -14).
        assert!(st
            .decrypt_seed_with_passphrase(Passphrase::from("wrong".to_string()))
            .is_err());
    }

    #[test]
    fn view_only_wallet_stores_no_seed() {
        let dir = tempfile::tempdir().unwrap();
        let kp = keys_path(dir.path());
        WalletStore::init_view_only(&kp, BlockHeight::from_u32(7), ZNetwork::Test, UFVK).unwrap();
        let st = WalletStore::read(&kp).unwrap();
        assert_eq!(st.pinned_ufvk(), Some(UFVK));
        assert!(!st.has_seed(), "a watch-only wallet has no stored mnemonic");
        assert!(
            !st.is_encrypted(),
            "no spending material, so nothing is passphrase-encrypted"
        );
        assert_eq!(st.network, ZNetwork::Test);
        assert_eq!(u32::from(st.birthday), 7);
        // Nothing to decrypt: the seed accessors yield None rather than erroring.
        let identity = age::x25519::Identity::generate();
        assert!(st
            .decrypt_seed(std::iter::once(&identity as &dyn age::Identity))
            .unwrap()
            .is_none());
    }

    #[test]
    fn missing_birthday_defaults_to_nu5() {
        // A hand-edited keys.toml without a birthday falls back to Orchard activation (NU5),
        // not the older Sapling-activation default - an Orchard-only wallet holds no earlier
        // notes. (`init` always writes a birthday, so this is only the defensive path.)
        let dir = tempfile::tempdir().unwrap();
        let kp = keys_path(dir.path());
        std::fs::write(&kp, "network = \"main\"\n").unwrap();
        let st = WalletStore::read(&kp).unwrap();
        assert_eq!(
            st.birthday,
            ZNetwork::Main
                .activation_height(NetworkUpgrade::Nu5)
                .expect("NU5 height")
        );
        // A pre-pin keys.toml reads back unpinned (the daemon backfills it at startup).
        assert_eq!(st.pinned_ufvk(), None);
    }

    #[test]
    fn identity_wallet_is_not_marked_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let kp = keys_path(dir.path());
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        WalletStore::init_with_mnemonic(
            &kp,
            std::iter::once(&recipient as &dyn age::Recipient),
            &mnemonic,
            BlockHeight::from_u32(1),
            ZNetwork::Test,
            UFVK,
        )
        .unwrap();
        let st = WalletStore::read(&kp).unwrap();
        assert!(!st.is_encrypted());
        assert!(st.has_seed());
        assert_eq!(st.pinned_ufvk(), Some(UFVK));
    }

    /// The backfill path: `pin_ufvk` adds the pin to a pre-pin file while preserving every
    /// other field, above all the mnemonic ciphertext (a corrupted rewrite here would brick
    /// the wallet), and keeps the file private (0600). Re-pinning the same value is a no-op.
    #[test]
    fn pin_ufvk_backfills_preserving_mnemonic_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let kp = keys_path(dir.path());
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        let passphrase = || Passphrase::from("correct horse battery".to_string());
        WalletStore::init_with_passphrase(
            &kp,
            passphrase(),
            &mnemonic,
            BlockHeight::from_u32(42),
            ZNetwork::Test,
            UFVK,
        )
        .unwrap();
        WalletStore::strip_pin_for_tests(&kp);
        assert_eq!(WalletStore::read(&kp).unwrap().pinned_ufvk(), None);

        WalletStore::pin_ufvk(&kp, UFVK).unwrap();
        let st = WalletStore::read(&kp).unwrap();
        assert_eq!(st.pinned_ufvk(), Some(UFVK));
        // Everything else survived the rewrite: the ciphertext still decrypts, and the
        // metadata round-trips.
        assert!(st.is_encrypted());
        assert_eq!(u32::from(st.birthday), 42);
        assert!(st
            .decrypt_seed_with_passphrase(passphrase())
            .unwrap()
            .is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&kp).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "keys.toml must stay private (0600)");
        }

        // Idempotent: re-pinning the identical value succeeds and changes nothing.
        let before = std::fs::read_to_string(&kp).unwrap();
        WalletStore::pin_ufvk(&kp, UFVK).unwrap();
        assert_eq!(std::fs::read_to_string(&kp).unwrap(), before);
    }
}
