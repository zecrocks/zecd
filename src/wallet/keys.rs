//! In-memory custody of the decrypted wallet seed and on-demand spending-key derivation.
//!
//! The seed is held as a zeroizing secret and never persisted in the clear. The Unified
//! Spending Key is derived fresh per send (mirrors `zcash-devtool/src/commands/wallet/send.rs`)
//! and never cached.

use std::path::Path;

use secrecy::{ExposeSecret, SecretVec};
use zcash_keys::keys::UnifiedSpendingKey;

use crate::error::RpcError;
use crate::hardening;
use crate::keystore::{self, Keystore};
use crate::network::ZNetwork;
use crate::wallet::store::WalletStore;

/// The decrypted seed held in `mlock`ed memory: the page(s) backing it are pinned into RAM
/// (best-effort) so the seed is never written to swap while unlocked, and `munlock`ed before
/// the bytes are zeroized and freed on drop. The inner `SecretVec` does the zeroizing.
struct MlockedSeed {
    seed: SecretVec<u8>,
    /// Whether `mlock` actually succeeded, so `munlock` is only called to match.
    locked: bool,
}

impl MlockedSeed {
    fn new(seed: SecretVec<u8>) -> Self {
        let locked = hardening::lock_secret(seed.expose_secret());
        MlockedSeed { seed, locked }
    }

    fn expose(&self) -> &[u8] {
        self.seed.expose_secret()
    }
}

impl Drop for MlockedSeed {
    fn drop(&mut self) {
        // Runs before the `seed` field is dropped (and zeroized), while its pages are still
        // mapped - the required order for `munlock`.
        hardening::unlock_secret(self.seed.expose_secret(), self.locked);
    }
}

/// Holds the decrypted seed (when unlocked). Sending requires this to be unlocked.
#[derive(Default)]
pub struct SeedKeeper {
    seed: Option<MlockedSeed>,
}

impl SeedKeeper {
    pub fn locked() -> Self {
        SeedKeeper { seed: None }
    }

    #[cfg(test)] // only the regtest lifecycle tests construct an already-unlocked keeper
    pub fn unlocked(seed: SecretVec<u8>) -> Self {
        SeedKeeper {
            seed: Some(MlockedSeed::new(seed)),
        }
    }

    pub fn lock(&mut self) {
        // Dropping the `MlockedSeed` munlocks then zeroizes the bytes.
        self.seed = None;
    }

    pub fn set(&mut self, seed: SecretVec<u8>) {
        self.seed = Some(MlockedSeed::new(seed));
    }

    /// Derive the Unified Spending Key for an account index, or return the bitcoind
    /// "unlock needed" error (-13) if the seed is not loaded.
    pub fn derive_usk(
        &self,
        network: ZNetwork,
        account_index: zip32::AccountId,
    ) -> Result<UnifiedSpendingKey, RpcError> {
        let seed = self.seed.as_ref().ok_or_else(RpcError::unlock_needed)?;
        UnifiedSpendingKey::from_seed(&network, seed.expose(), account_index)
            .map_err(|e| RpcError::wallet(format!("key derivation failed: {e}")))
    }
}

/// Load age identities from a file and decrypt the wallet's stored seed.
pub fn decrypt_seed_with_identity(
    store: &WalletStore,
    identity_path: &Path,
) -> anyhow::Result<Option<SecretVec<u8>>> {
    let identities = age::IdentityFile::from_file(identity_path.to_string_lossy().into_owned())?
        .into_identities()?;
    store.decrypt_seed(identities.iter().map(|i| i.as_ref() as _))
}

/// Load age identities and decrypt the stored mnemonic to its raw phrase bytes (not the seed).
/// Used by `zecd rewrap` to re-wrap an identity-encrypted mnemonic under a passphrase or KMS key.
pub fn decrypt_mnemonic_with_identity(
    store: &WalletStore,
    identity_path: &Path,
) -> anyhow::Result<Option<SecretVec<u8>>> {
    let identities = age::IdentityFile::from_file(identity_path.to_string_lossy().into_owned())?
        .into_identities()?;
    store.decrypt_mnemonic(identities.iter().map(|i| i.as_ref() as _))
}

/// Build the [`Keystore`] that can unwrap a KMS wallet's identity: provider and key come
/// from the wallet's own `keys.toml` (it describes its ciphertext); only the endpoint
/// override comes from `[keystore]` config.
fn keystore_for(store: &WalletStore, endpoint: Option<&str>) -> anyhow::Result<Keystore> {
    let info = store
        .kms()
        .ok_or_else(|| anyhow::anyhow!("wallet is not KMS-wrapped"))?;
    Ok(Keystore {
        provider: info.provider,
        key: info.key.clone(),
        endpoint: endpoint.map(String::from),
    })
}

/// Unwrap a KMS wallet's age identity (one cloud Decrypt call) and decrypt the stored
/// mnemonic into the BIP-39 seed. The startup auto-unlock path for `encryption = "kms"`.
pub async fn decrypt_seed_with_keystore(
    store: &WalletStore,
    endpoint: Option<&str>,
) -> anyhow::Result<Option<SecretVec<u8>>> {
    let keystore = keystore_for(store, endpoint)?;
    let info = store.kms().expect("checked by keystore_for");
    let ctx = store.kms_context().expect("present iff kms");
    let identity = keystore::unwrap_identity(&keystore, &info.wrapped_identity, &ctx).await?;
    store.decrypt_seed(std::iter::once(&identity as &dyn age::Identity))
}

/// Unwrap a KMS wallet's age identity and decrypt the stored mnemonic to its raw phrase
/// bytes. Used by `zecd rewrap` (migration off KMS onto a passphrase, or KMS key rotation).
pub async fn decrypt_mnemonic_with_keystore(
    store: &WalletStore,
    endpoint: Option<&str>,
) -> anyhow::Result<Option<SecretVec<u8>>> {
    let keystore = keystore_for(store, endpoint)?;
    let info = store.kms().expect("checked by keystore_for");
    let ctx = store.kms_context().expect("present iff kms");
    let identity = keystore::unwrap_identity(&keystore, &info.wrapped_identity, &ctx).await?;
    store.decrypt_mnemonic(std::iter::once(&identity as &dyn age::Identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip0039::{English, Mnemonic};
    use zcash_protocol::consensus::BlockHeight;

    use crate::wallet::store::WalletStore;

    // The committed testnet test mnemonic (valueless TAZ only). Reused here purely as a
    // deterministic seed source for the custody round-trips.
    const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    fn account_zero() -> zip32::AccountId {
        zip32::AccountId::try_from(0u32).unwrap()
    }

    fn test_seed_secret() -> SecretVec<u8> {
        let seed = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        SecretVec::new(seed.to_vec())
    }

    /// A locked keeper holds no seed, so any key derivation is the bitcoind -13
    /// "unlock needed" error rather than a panic or a wrong key.
    #[test]
    fn locked_keeper_refuses_key_derivation_with_minus_13() {
        let keeper = SeedKeeper::locked();
        let err = keeper
            .derive_usk(ZNetwork::Test, account_zero())
            .expect_err("a locked keeper cannot derive a spending key");
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_UNLOCK_NEEDED);

        // `Default` (used by the actor before the first unlock) is equivalent to locked.
        let err = SeedKeeper::default()
            .derive_usk(ZNetwork::Test, account_zero())
            .expect_err("the default keeper is locked");
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_UNLOCK_NEEDED);
    }

    /// The unlock → derive → lock lifecycle: loading the seed enables derivation,
    /// the same seed derives identical key material (determinism - a same-seed
    /// restore/watch-only pair must share an account), and locking drops the seed so
    /// derivation needs an unlock again.
    #[test]
    fn seed_keeper_unlock_derive_lock_cycle() {
        let acct = account_zero();
        let mut keeper = SeedKeeper::locked();
        keeper.set(test_seed_secret());

        let usk1 = keeper
            .derive_usk(ZNetwork::Test, acct)
            .expect("unlocked: derive");
        let usk2 = keeper
            .derive_usk(ZNetwork::Test, acct)
            .expect("unlocked: derive again");
        assert_eq!(
            usk1.to_unified_full_viewing_key().encode(&ZNetwork::Test),
            usk2.to_unified_full_viewing_key().encode(&ZNetwork::Test),
            "the same seed must derive identical key material"
        );

        keeper.lock();
        let err = keeper
            .derive_usk(ZNetwork::Test, acct)
            .expect_err("a re-locked keeper cannot derive");
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_UNLOCK_NEEDED);
    }

    /// The identity-file unlock path (the legacy/unencrypted model): an on-disk age
    /// identity decrypts the wallet's stored mnemonic back to the exact BIP-39 seed.
    #[test]
    fn decrypt_seed_with_identity_reads_identity_file() {
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

        // Write the identity file exactly as `zecd init` does.
        let id_path = dir.path().join("identity.txt");
        {
            use age::secrecy::ExposeSecret as _;
            std::fs::write(&id_path, identity.to_string().expose_secret()).unwrap();
        }

        let st = WalletStore::read(dir.path()).unwrap();
        let seed = decrypt_seed_with_identity(&st, &id_path)
            .unwrap()
            .expect("the wallet has a stored mnemonic");
        let expected = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);
    }

    /// Asking the KMS unlock path to open a non-KMS wallet must fail loudly (and before
    /// any network I/O), not silently fall through.
    #[tokio::test]
    async fn decrypt_seed_with_keystore_rejects_non_kms_wallet() {
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
        let err = decrypt_seed_with_keystore(&st, None)
            .await
            .err()
            .expect("a non-KMS wallet has no key to unwrap")
            .to_string();
        assert!(err.contains("not KMS-wrapped"), "got: {err}");
    }
}

/// KMS auto-unlock glue, exercised against the in-process fake KMS server. Feature-gated
/// with the providers themselves (without the `keystore` feature there is no cloud client).
#[cfg(all(test, feature = "keystore"))]
mod kms_tests {
    use super::*;
    use bip0039::{English, Mnemonic};
    use zcash_protocol::consensus::BlockHeight;

    use crate::keystore::{fake, Keystore, KeystoreProvider, WrapContext};
    use crate::wallet::store::{KmsInfo, Passphrase, WalletStore};

    const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";
    const KEY: &str = "arn:aws:kms:us-east-1:111122223333:key/keys-rs-test";

    /// Wrap a fresh age identity under the fake KMS bound to `wrap_wallet`, then create a
    /// KMS-model wallet whose `keys.toml` records `stored_wallet` as the context wallet.
    /// When the two differ, the unlock presents the wrong encryption context.
    async fn init_kms_wallet(
        dir: &std::path::Path,
        endpoint: &str,
        wrap_wallet: &str,
        stored_wallet: &str,
    ) {
        let identity = age::x25519::Identity::generate();
        let ctx = WrapContext {
            wallet: wrap_wallet.to_string(),
            network: "test".to_string(),
        };
        let ks = Keystore {
            provider: KeystoreProvider::AwsKms,
            key: KEY.to_string(),
            endpoint: Some(endpoint.to_string()),
        };
        let wrapped = {
            use age::secrecy::ExposeSecret as _;
            ks.wrap(identity.to_string().expose_secret().as_bytes(), &ctx)
                .await
                .unwrap()
        };
        let info = KmsInfo {
            provider: KeystoreProvider::AwsKms,
            key: KEY.to_string(),
            wrapped_identity: wrapped,
            context_wallet: stored_wallet.to_string(),
        };
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        WalletStore::init_with_kms(
            dir,
            &identity.to_public(),
            &info,
            &mnemonic,
            BlockHeight::from_u32(1),
            ZNetwork::Test,
        )
        .unwrap();
    }

    /// The startup auto-unlock for `encryption = "kms"`: one KMS Decrypt unwraps the
    /// identity and recovers the exact BIP-39 seed.
    #[tokio::test(flavor = "multi_thread")]
    async fn decrypt_seed_with_keystore_unlocks_kms_wallet() {
        fake::set_fake_credentials();
        let endpoint = fake::spawn_aws(KEY).await;
        let dir = tempfile::tempdir().unwrap();
        init_kms_wallet(dir.path(), &endpoint, "default", "default").await;

        let st = WalletStore::read(dir.path()).unwrap();
        let seed = decrypt_seed_with_keystore(&st, Some(&endpoint))
            .await
            .unwrap()
            .expect("KMS wallet has a stored mnemonic");
        let expected = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);
    }

    /// The encryption-context binding is enforced end-to-end: if the wallet's recorded
    /// context no longer matches what the ciphertext was bound to, the unlock fails
    /// (returns an `Err` the actor retries with backoff) rather than yielding a wrong seed.
    #[tokio::test(flavor = "multi_thread")]
    async fn kms_unlock_surfaces_error_on_context_mismatch() {
        fake::set_fake_credentials();
        let endpoint = fake::spawn_aws(KEY).await;
        let dir = tempfile::tempdir().unwrap();
        // Wrapped bound to "default", but keys.toml records "renamed".
        init_kms_wallet(dir.path(), &endpoint, "default", "renamed").await;

        let st = WalletStore::read(dir.path()).unwrap();
        let res = decrypt_seed_with_keystore(&st, Some(&endpoint)).await;
        assert!(
            res.is_err(),
            "a context mismatch must surface as a retryable error, not a wrong seed"
        );
    }

    /// The `zecd rewrap` KMS->passphrase migration, exercised offline at the keys/store
    /// layer: unwrap the mnemonic via one KMS Decrypt, re-wrap it under a passphrase, and
    /// confirm the wallet is now Bitcoin-Core-encrypted, opens with the passphrase to the same
    /// seed, and no longer has any cloud path.
    #[tokio::test(flavor = "multi_thread")]
    async fn kms_to_passphrase_migration_roundtrips() {
        const PASS: &str = "correct horse battery staple";
        fake::set_fake_credentials();
        let endpoint = fake::spawn_aws(KEY).await;
        let dir = tempfile::tempdir().unwrap();
        init_kms_wallet(dir.path(), &endpoint, "default", "default").await;

        // Step 1 - read the mnemonic back via KMS (rewrap's KMS branch).
        let st = WalletStore::read(dir.path()).unwrap();
        let mnemonic = decrypt_mnemonic_with_keystore(&st, Some(&endpoint))
            .await
            .unwrap()
            .expect("KMS wallet has a stored mnemonic");
        let phrase = std::str::from_utf8(mnemonic.expose_secret()).unwrap();

        // Step 2 - re-wrap under a passphrase, dropping the [kms] table.
        st.rewrite_with_passphrase(dir.path(), Passphrase::from(PASS.to_string()), phrase)
            .unwrap();

        // The wallet is now Bitcoin-Core-encrypted and the cloud path is gone.
        let st = WalletStore::read(dir.path()).unwrap();
        assert!(
            st.is_encrypted(),
            "after migration the wallet is passphrase-encrypted"
        );
        assert!(st.kms().is_none(), "the [kms] table must be dropped");

        // It opens with the passphrase, recovering the exact seed...
        let seed = st
            .decrypt_seed_with_passphrase(Passphrase::from(PASS.to_string()))
            .unwrap()
            .unwrap();
        let expected = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);

        // ...and the KMS unlock path now refuses (no [kms] table left to unwrap).
        let err = decrypt_seed_with_keystore(&st, Some(&endpoint))
            .await
            .err()
            .expect("a migrated wallet has no KMS metadata")
            .to_string();
        assert!(err.contains("not KMS-wrapped"), "got: {err}");
    }
}
