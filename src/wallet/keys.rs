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

/// Refuse to load an age identity from anything but a regular file with owner-only
/// permissions. The file holds the secret key that decrypts the wallet mnemonic, so:
///
/// - **Permissions:** any group/other access bit (`mode & 0o077 != 0`) is rejected, because a
///   world-/group-readable identity leaks the wallet to other local users. `zecd init` creates
///   it `0600`, but nothing stops a later `chmod`, so this re-checks on every load, mirroring
///   SSH's refusal to use an over-permissive private key.
/// - **File type:** the load target must resolve to a regular file (not a directory, device,
///   fifo, or socket).
///
/// On the symlink question: we deliberately resolve *through* a symlink
/// (`std::fs::metadata` follows it) rather than rejecting symlinks outright as OpenSSH does.
/// A Kubernetes Secret/ConfigMap volume presents each mounted file as a symlink into its
/// `..data/` directory, and zecd supports mounting the age identity as a Secret
/// (`ZECD_AGE_IDENTITY`), so a hard "regular file only, no symlinks" rule would break that
/// deployment. Validating the *resolved* target's type and mode keeps the Secret mount working
/// while still enforcing owner-only access on the real file (a group/other-readable target is
/// rejected whether or not a symlink points at it). Planting a hostile symlink additionally
/// requires write access to the identity's parent directory, which is already outside zecd's
/// trust boundary, and a foreign identity cannot decrypt the operator's own `keys.toml`.
///
/// Best-effort and a no-op on non-unix targets (no POSIX mode bits to inspect).
pub fn check_identity_file_permissions(identity_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use anyhow::Context as _;
        use std::os::unix::fs::PermissionsExt as _;

        // `metadata` follows symlinks, so this is the *resolved target's* metadata (see the
        // Kubernetes-Secret rationale above). A dangling symlink surfaces here as a read error
        // and fails closed.
        let meta = std::fs::metadata(identity_path).with_context(|| {
            format!("reading the age identity file {}", identity_path.display())
        })?;
        if !meta.is_file() {
            anyhow::bail!(
                "age identity path {path} does not resolve to a regular file; refusing to load \
                 the wallet's decryption key from an unexpected file type",
                path = identity_path.display(),
            );
        }
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "age identity file {path} has insecure permissions {mode:#o}: it is accessible \
                 to group/other and could leak the wallet seed to other local users. It must be \
                 readable only by its owner. (try chmod 600)",
                path = identity_path.display(),
                mode = mode & 0o7777,
            );
        }
    }
    #[cfg(not(unix))]
    let _ = identity_path;
    Ok(())
}

/// Load age identities from a file and decrypt the wallet's stored seed.
pub fn decrypt_seed_with_identity(
    store: &WalletStore,
    identity_path: &Path,
) -> anyhow::Result<Option<SecretVec<u8>>> {
    check_identity_file_permissions(identity_path)?;
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
            "uviewtest1keystestplaceholder",
        )
        .unwrap();

        // Write the identity file with owner-only permissions, as `zecd init` does (and as the
        // load-time permission check now requires).
        let id_path = dir.path().join("identity.txt");
        {
            use age::secrecy::ExposeSecret as _;
            std::fs::write(&id_path, identity.to_string().expose_secret()).unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let st = WalletStore::read(&kp).unwrap();
        let seed = decrypt_seed_with_identity(&st, &id_path)
            .unwrap()
            .expect("the wallet has a stored mnemonic");
        let expected = <Mnemonic<English>>::from_phrase(PHRASE)
            .unwrap()
            .to_seed("");
        assert_eq!(seed.expose_secret().as_slice(), &expected[..]);

        // Widening the identity's permissions makes the same load refuse it (SSH-style),
        // rather than silently decrypting with a seed exposed to other local users.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            // `Option<SecretVec>` isn't `Debug`, so match rather than `expect_err`.
            match decrypt_seed_with_identity(&st, &id_path) {
                Err(err) => assert!(
                    err.to_string().contains("insecure permissions"),
                    "unexpected error: {err}"
                ),
                Ok(_) => panic!("a group/other-readable identity must be refused"),
            }
        }
    }

    /// The permission gate: owner-only modes load, any group/other access bit refuses.
    #[cfg(unix)]
    #[test]
    fn check_identity_file_permissions_rejects_overbroad_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        std::fs::write(&path, b"# identity\n").unwrap();

        for ok in [0o600, 0o400] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(ok)).unwrap();
            check_identity_file_permissions(&path)
                .unwrap_or_else(|e| panic!("mode {ok:#o} should be accepted: {e}"));
        }

        for bad in [0o640, 0o604, 0o660, 0o606, 0o644, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(bad)).unwrap();
            assert!(
                check_identity_file_permissions(&path).is_err(),
                "mode {bad:#o} (group/other-accessible) must be rejected"
            );
        }
    }

    /// Audit 3.7 file-type + symlink handling: a non-regular file is rejected; a symlink is
    /// resolved (so a Kubernetes Secret mount works) and its *target's* mode is what's enforced.
    #[cfg(unix)]
    #[test]
    fn check_identity_file_permissions_requires_regular_target() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();

        // A directory at the path is not a regular file -> rejected.
        let as_dir = dir.path().join("identity_dir");
        std::fs::create_dir(&as_dir).unwrap();
        assert!(
            check_identity_file_permissions(&as_dir).is_err(),
            "a non-regular file (directory) must be rejected"
        );

        // A symlink to a 0600 regular file (the k8s-Secret shape) is accepted: we follow the
        // link and validate the target.
        let target = dir.path().join("real_identity.txt");
        std::fs::write(&target, b"# identity\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("identity_link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        check_identity_file_permissions(&link)
            .expect("a symlink to a 0600 regular file must be accepted (k8s Secret mount)");

        // The mode check applies to the resolved target: widen it and the symlink load refuses.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            check_identity_file_permissions(&link).is_err(),
            "a symlink whose target is group/other-readable must be rejected"
        );

        // A dangling symlink fails closed (read error), never silently loads.
        let dangling = dir.path().join("dangling.txt");
        std::os::unix::fs::symlink(dir.path().join("nope"), &dangling).unwrap();
        assert!(
            check_identity_file_permissions(&dangling).is_err(),
            "a dangling symlink must fail closed"
        );
    }
}
