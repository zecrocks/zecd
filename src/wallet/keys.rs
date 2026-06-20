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

    /// Whether the seed is currently loaded (the wallet is unlocked).
    pub fn is_unlocked(&self) -> bool {
        self.seed.is_some()
    }

    /// A copy of the decrypted seed, if loaded - for recreating the wallet account from
    /// `keys.toml` on an empty datadir (the bootstrap path). The returned `SecretVec` zeroizes on
    /// drop; the copy is short-lived and not `mlock`ed, matching the transient exposure that
    /// `derive_usk` already makes during a send.
    pub fn clone_seed(&self) -> Option<SecretVec<u8>> {
        self.seed
            .as_ref()
            .map(|s| SecretVec::new(s.expose().to_vec()))
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
        let kp = crate::wallet::store::keys_path(dir.path());
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let mnemonic = <Mnemonic<English>>::from_phrase(PHRASE).unwrap();
        WalletStore::init_with_mnemonic(
            &kp,
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

        let st = WalletStore::read(&kp).unwrap();
        let seed = decrypt_seed_with_identity(&st, &id_path)
            .unwrap()
            .expect("the wallet has a stored mnemonic");
        let expected = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);
    }
}
