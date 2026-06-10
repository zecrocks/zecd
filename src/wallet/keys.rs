//! In-memory custody of the decrypted wallet seed and on-demand spending-key derivation.
//!
//! The seed is held as a zeroizing secret and never persisted in the clear. The Unified
//! Spending Key is derived fresh per send (mirrors `zcash-devtool/src/commands/wallet/send.rs`)
//! and never cached.
#![allow(dead_code)] // `unlocked` constructor kept for completeness

use std::path::Path;

use secrecy::{ExposeSecret, SecretVec};
use zcash_keys::keys::UnifiedSpendingKey;

use crate::error::RpcError;
use crate::network::ZNetwork;
use crate::wallet::store::WalletStore;

/// Holds the decrypted seed (when unlocked). Sending requires this to be unlocked.
#[derive(Default)]
pub struct SeedKeeper {
    seed: Option<SecretVec<u8>>,
}

impl SeedKeeper {
    pub fn locked() -> Self {
        SeedKeeper { seed: None }
    }

    pub fn unlocked(seed: SecretVec<u8>) -> Self {
        SeedKeeper { seed: Some(seed) }
    }

    pub fn is_unlocked(&self) -> bool {
        self.seed.is_some()
    }

    pub fn lock(&mut self) {
        self.seed = None;
    }

    pub fn set(&mut self, seed: SecretVec<u8>) {
        self.seed = Some(seed);
    }

    /// Derive the Unified Spending Key for an account index, or return the bitcoind
    /// "unlock needed" error (-13) if the seed is not loaded.
    pub fn derive_usk(
        &self,
        network: ZNetwork,
        account_index: zip32::AccountId,
    ) -> Result<UnifiedSpendingKey, RpcError> {
        let seed = self.seed.as_ref().ok_or_else(RpcError::unlock_needed)?;
        UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), account_index)
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
