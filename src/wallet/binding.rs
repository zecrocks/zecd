//! Account-to-keys binding: the cryptographic tie between the wallet database's account and
//! `keys.toml`, zecd's root of trust.
//!
//! The wallet database (`data.sqlite`) is a rebuildable cache of on-chain data, but one datum
//! in it is security-critical and has no on-chain check: *which account the daemon serves*.
//! `getnewaddress` derives receive addresses from the DB account's UFVK, so a planted or
//! swapped database silently diverts every future deposit to whoever holds that account's
//! keys. The audit's "initialization trusts the existing contents of the data directory"
//! observation is one instance; substituting the database *after* init is another.
//!
//! The defense is a pin, not a hash: `keys.toml` (0600, operator-controlled, and already the
//! at-rest home of the mnemonic) records the account's Unified Full Viewing Key at init. The
//! UFVK is derivable from the seed, so the pin is a cache of seed-derivable data and respects
//! zecd's statelessness invariant (see the project docs). Four layers use it:
//!
//! 1. `zecd init` refuses a wallet database that already contains an account
//!    (`init::ensure_no_preexisting_account`).
//! 2. `zecd init` pins the new account's UFVK into `keys.toml` (all three custody models).
//! 3. Every startup verifies the DB-selected account against the pin and fails closed on a
//!    mismatch ([`verify_or_pin_account`]). A pre-pin (legacy) `keys.toml` is upgraded by
//!    pinning the current account, trust-on-first-use.
//! 4. Every unlock (identity auto-unlock at startup, `walletpassphrase` at runtime) verifies
//!    that the decrypted seed actually derives the account's UFVK ([`seed_ufvk_encoded`]),
//!    which retroactively validates a trust-on-first-use pin and catches a `keys.toml` +
//!    database pair swapped in together.
//!
//! Deliberately *not* covered: tampering with non-key rows (notes, tx history, scan state).
//! Once the account keys are verified, planted notes cannot be spent and balances are
//! rebuildable from seed + chain; byte-level integrity of a live SQLite database is a
//! filesystem/deployment concern, not the daemon's.

use std::path::Path;

use anyhow::anyhow;
use secrecy::{ExposeSecret as _, SecretVec};
use tracing::info;
use zcash_client_backend::data_api::{Account as _, WalletRead as _};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedSpendingKey;

use crate::network::ZNetwork;
use crate::wallet::open::WriteDb;
use crate::wallet::store::WalletStore;

/// A failed binding check: evidence that the wallet database or `keys.toml` was replaced or
/// belongs to a different wallet. Typed (rather than a bare `anyhow!`) so `daemon::run` can
/// tell it apart from ordinary per-wallet startup failures: an unreadable wallet is skipped
/// with an error log, but tampering evidence takes the whole daemon down, like the
/// single-spending-wallet invariant.
#[derive(Debug)]
pub struct BindingMismatch(pub String);

impl std::fmt::Display for BindingMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BindingMismatch {}

/// The network-scoped string encoding of the account's Unified Full Viewing Key. This is the
/// canonical form for pinning and comparison (the same encoding `zecd export-ufvk` prints).
pub fn account_ufvk_encoded(
    network: ZNetwork,
    db: &WriteDb,
    id: AccountUuid,
) -> anyhow::Result<String> {
    let account = db
        .get_account(id)?
        .ok_or_else(|| anyhow!("selected account not found in the wallet database"))?;
    let ufvk = account
        .ufvk()
        .ok_or_else(|| anyhow!("account has no unified full viewing key"))?;
    Ok(ufvk.encode(&network))
}

/// The UFVK (network-scoped encoding) that `seed` derives at ZIP-32 account `index`. This is
/// what `create_account` stores for a fresh wallet, so comparing it against
/// [`account_ufvk_encoded`] proves the seed and the database describe the same wallet.
pub fn seed_ufvk_encoded(
    network: ZNetwork,
    seed: &SecretVec<u8>,
    index: zip32::AccountId,
) -> anyhow::Result<String> {
    let usk = UnifiedSpendingKey::from_seed(&network, seed.expose_secret(), index)
        .map_err(|_| anyhow!("deriving the unified spending key from the seed failed"))?;
    Ok(usk.to_unified_full_viewing_key().encode(&network))
}

/// The startup binding check (layer 3). `pinned` is `keys.toml`'s recorded UFVK,
/// `account_ufvk` the database account's:
///
/// - equal: verified, nothing to do;
/// - different: fail closed. The database was replaced or belongs to a different wallet, and
///   serving it would hand out another key's receive addresses;
/// - no pin (a `keys.toml` from before this field existed): pin the current account,
///   trust-on-first-use. The next seed exposure (auto-unlock or `walletpassphrase`) verifies
///   the pinned account against the seed, so a wrong TOFU pin cannot survive an unlock.
pub fn verify_or_pin_account(
    name: &str,
    keys_path: &Path,
    pinned: Option<&str>,
    account_ufvk: &str,
) -> anyhow::Result<()> {
    match pinned {
        Some(p) if p == account_ufvk => Ok(()),
        Some(p) => Err(anyhow::Error::new(BindingMismatch(format!(
            "wallet '{name}': the account in the wallet database does not match the key pinned \
             in keys.toml (pinned {}, database has {}). The database was replaced or belongs to \
             a different wallet; refusing to serve it. Restore the matching database, or re-run \
             `zecd init` in a fresh data directory.",
            abbrev(p),
            abbrev(account_ufvk)
        )))),
        None => {
            WalletStore::pin_ufvk(keys_path, account_ufvk)?;
            info!(
                "[{name}] pinned the wallet account's unified full viewing key into keys.toml \
                 (pre-existing wallet upgraded); future startups verify the wallet database \
                 against this pin"
            );
            Ok(())
        }
    }
}

/// Abbreviate a UFVK for log/error output. The full encoding is hundreds of characters and is
/// itself a viewing capability, so error paths print only enough of it to compare by eye.
fn abbrev(ufvk: &str) -> String {
    const KEEP: usize = 24;
    if ufvk.len() <= KEEP {
        ufvk.to_string()
    } else {
        format!("{}...", &ufvk[..KEEP])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bip0039::{English, Mnemonic};
    use secrecy::Zeroize;
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_client_backend::data_api::{AccountBirthday, WalletWrite as _};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;

    use crate::network;
    use crate::wallet::open;
    use crate::wallet::store::{keys_path, Passphrase};

    /// The committed testnet test mnemonic (valueless), as a deterministic seed source.
    const TEST_PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    /// A second, unrelated seed (the standard BIP-39 "abandon...art" vector) for the
    /// foreign-wallet negative cases.
    const FOREIGN_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon art";

    fn seed_from(phrase: &str) -> SecretVec<u8> {
        let mut seed = <Mnemonic<English>>::from_phrase(phrase)
            .unwrap()
            .to_seed("");
        let secret = SecretVec::new(seed.to_vec());
        seed.zeroize();
        secret
    }

    fn genesis_birthday() -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
            None,
        )
    }

    fn account_index_zero() -> zip32::AccountId {
        zip32::AccountId::try_from(0u32).unwrap()
    }

    /// The load-bearing equivalence: the UFVK this module derives from a seed at index 0 is
    /// byte-for-byte the one `create_account` stores for that seed. If these derivations ever
    /// diverged, every fresh wallet would fail its own startup check; `init` cross-checks the
    /// same equivalence at wallet creation so a divergence surfaces there first.
    #[test]
    fn seed_derivation_matches_created_account() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let mut db = open::init_dbs(net, dir.path()).unwrap();
        let seed = seed_from(TEST_PHRASE);
        let (id, _usk) = db
            .create_account("primary", &seed, &genesis_birthday(), None)
            .unwrap();

        let from_db = account_ufvk_encoded(net, &db, id).unwrap();
        let from_seed = seed_ufvk_encoded(net, &seed, account_index_zero()).unwrap();
        assert_eq!(from_db, from_seed);

        // A foreign seed derives a different UFVK, so the mismatch the binding checks for is
        // actually observable.
        let foreign =
            seed_ufvk_encoded(net, &seed_from(FOREIGN_PHRASE), account_index_zero()).unwrap();
        assert_ne!(from_db, foreign);
    }

    /// The watch-only pin path relies on the UFVK encoding being canonical: `init --ufvk` pins
    /// `encode(parse(input))` and startup compares it against `encode(<DB account's key>)`,
    /// so re-encoding a decoded key must be byte-for-byte stable. Also proves the pin survives
    /// an `import_account_ufvk` round trip through the database.
    #[test]
    fn ufvk_encoding_roundtrip_is_canonical() {
        use zcash_client_backend::data_api::AccountPurpose;
        use zcash_keys::keys::UnifiedFullViewingKey;

        let net = network::regtest();
        let encoded =
            seed_ufvk_encoded(net, &seed_from(TEST_PHRASE), account_index_zero()).unwrap();
        let parsed = UnifiedFullViewingKey::decode(&net, &encoded).unwrap();
        assert_eq!(parsed.encode(&net), encoded, "encode(decode(x)) == x");

        // Import the parsed key view-only (what `init --ufvk` does) and confirm the account
        // read back from the database still encodes to the pinned value.
        let dir = tempfile::tempdir().unwrap();
        let mut db = open::init_dbs(net, dir.path()).unwrap();
        let account = db
            .import_account_ufvk(
                "watch",
                &parsed,
                &genesis_birthday(),
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap();
        use zcash_client_backend::data_api::Account as _;
        let from_db = account_ufvk_encoded(net, &db, account.id()).unwrap();
        assert_eq!(
            from_db, encoded,
            "the imported account re-encodes to the pin"
        );
    }

    /// `verify_or_pin_account` policy: match passes, mismatch fails closed, absence pins.
    #[test]
    fn verify_or_pin_policy() {
        let net = network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let kp = keys_path(dir.path());
        let seed = seed_from(TEST_PHRASE);
        let ufvk = seed_ufvk_encoded(net, &seed, account_index_zero()).unwrap();
        let foreign =
            seed_ufvk_encoded(net, &seed_from(FOREIGN_PHRASE), account_index_zero()).unwrap();

        // A legacy keys.toml (no pin field): the check pins trust-on-first-use.
        let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
        WalletStore::init_with_passphrase(
            &kp,
            Passphrase::from("correct horse battery".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            net,
            &ufvk,
        )
        .unwrap();
        WalletStore::strip_pin_for_tests(&kp);
        assert_eq!(WalletStore::read(&kp).unwrap().pinned_ufvk(), None);
        verify_or_pin_account("w", &kp, None, &ufvk).unwrap();
        let st = WalletStore::read(&kp).unwrap();
        assert_eq!(st.pinned_ufvk(), Some(ufvk.as_str()), "TOFU pin recorded");

        // A matching pin passes and leaves the file alone.
        verify_or_pin_account("w", &kp, st.pinned_ufvk(), &ufvk).unwrap();

        // A mismatched account fails closed and does not overwrite the pin.
        let err = verify_or_pin_account("w", &kp, st.pinned_ufvk(), &foreign).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("does not match"), "{msg}");
        assert!(
            !msg.contains(&ufvk) && !msg.contains(&foreign),
            "the error must not leak full viewing keys: {msg}"
        );
        assert_eq!(
            WalletStore::read(&kp).unwrap().pinned_ufvk(),
            Some(ufvk.as_str()),
            "a mismatch must never rewrite the pin"
        );
    }
}
