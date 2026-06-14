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
/// Used by `encryptwallet` to re-wrap an identity-encrypted mnemonic under a passphrase.
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
/// bytes. Used by `encryptwallet` (migration off KMS onto a passphrase) and `zecd rewrap`
/// (KMS key rotation).
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
