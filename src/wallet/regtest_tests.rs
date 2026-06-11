//! Offline regtest wallet-lifecycle test.
//!
//! Real zebra/zcashd regtest can't fund an Orchard-only wallet on-chain (coinbase is
//! transparent-only, there is no Orchard coinbase, and shielding regtest coinbase is blocked
//! upstream), and librustzcash's funded test harness (`zcash_client_sqlite`'s `TestDbFactory`)
//! is crate-private - so an actual *funded* note can't be materialised here. What we can do
//! deterministically and offline is drive zecd's own regtest code path end to end: initialise
//! the wallet DB on regtest, create an account, derive/encode a regtest Unified Address, and
//! exercise the read + key-derivation helpers. This is exactly the regtest plumbing the live
//! `deploy/regtest` stack relies on. Funded receive/spend is covered separately by the live
//! testnet flow (see the project docs) and by the harness's insufficient-funds (`-6`) check.

use bip0039::{English, Mnemonic};
use secrecy::{SecretVec, Zeroize};
use zcash_client_backend::data_api::chain::ChainState;
use zcash_client_backend::data_api::{AccountBirthday, WalletWrite};
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::network;
use crate::wallet::keys::SeedKeeper;
use crate::wallet::{open, read};

/// The committed testnet test mnemonic (valueless TAZ wallet); reused here purely as a
/// deterministic seed source for a throwaway regtest wallet.
const TEST_PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
    midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
    moment stage";

fn test_seed() -> SecretVec<u8> {
    let mut seed = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap().to_seed("");
    let secret = SecretVec::new(seed.to_vec());
    seed.zeroize();
    secret
}

/// A regtest birthday at genesis (Sapling activates at height 1 on our regtest), with an
/// empty prior chain state - needs no lightwalletd.
fn genesis_birthday() -> AccountBirthday {
    AccountBirthday::from_parts(
        ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
        None,
    )
}

#[test]
fn regtest_wallet_lifecycle() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = dir.path();

    // 1. Initialise the wallet DB on regtest and create an account from the seed.
    let mut db = open::init_dbs(net, wallet_dir).expect("init regtest dbs");
    let (account_id, _usk) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");

    // The actor learns the chain tip from the sync loop; address generation consults it, so
    // set a tip directly (no blocks scanned - this just records the height).
    db.update_chain_tip(BlockHeight::from_u32(1))
        .expect("set regtest chain tip");

    // 2. Derive an Orchard Unified Address and confirm it encodes with the regtest HRP.
    let (ua, _) = db
        .get_next_available_address(account_id, UnifiedAddressRequest::ORCHARD)
        .expect("address query")
        .expect("an address is available for a fresh account");
    let addr = ua.encode(&net);
    assert!(
        addr.starts_with("uregtest1"),
        "regtest UA should use the uregtest1 HRP, got {addr}"
    );

    // Release the writer connection before the read helpers open their own.
    drop(db);

    // 3. Read helpers operate on a regtest wallet: empty-but-valid balances and note set.
    let bal = read::balance(net, wallet_dir).expect("balance");
    assert_eq!(bal.total_spendable, 0);
    assert_eq!(bal.pending, 0);
    assert!(read::list_unspent(net, wallet_dir)
        .expect("listunspent")
        .is_empty());

    // 4. is_mine is network-scoped: true for our own regtest address, false for a testnet UA.
    assert!(
        read::is_mine(net, wallet_dir, &addr),
        "the wallet's own regtest address is mine"
    );
    let testnet_ua = "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";
    assert!(
        !read::is_mine(net, wallet_dir, testnet_ua),
        "a testnet address is not valid on regtest"
    );

    // 5. zecd's send-path key derivation works on regtest (USK from the seed at account 0).
    let account_index = zip32::AccountId::try_from(0u32).unwrap();
    SeedKeeper::unlocked(test_seed())
        .derive_usk(net, account_index)
        .expect("derive USK on regtest");
}

// --- Actor-level encryption plumbing (offline, but `#[ignore]`d because `actor::spawn` loads the
// bundled Sapling prover, which is slow). Run with `cargo test -- --include-ignored`. The actor
// serves walletpassphrase/walletlock commands even while its lightwalletd connection is failing,
// so a dead server endpoint is fine here. ---

use std::time::Duration;

use crate::error::codes;
use crate::lightwalletd::{self, TlsRoots};
use crate::wallet::actor::{self, ActorConfig};
use crate::wallet::store::{Passphrase, WalletStore};

/// An ActorConfig pointed at a dead local endpoint (connect fails fast; the actor still runs).
/// The returned shutdown sender must be kept alive for the actor's lifetime (dropping it is
/// itself a shutdown signal).
fn offline_actor_cfg(
    name: &str,
    wallet_dir: std::path::PathBuf,
) -> (ActorConfig, tokio::sync::watch::Sender<bool>) {
    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let net = network::regtest();
    let cfg = ActorConfig {
        name: name.to_string(),
        network: net,
        wallet_dir,
        servers: lightwalletd::resolve("127.0.0.1:1", net, TlsRoots::Native, Some(false), None)
            .unwrap(),
        sync_interval: Duration::from_secs(60),
        rebroadcast_interval: Duration::from_secs(60),
        connect_timeout: Duration::from_millis(150),
        reconnect_base: Duration::from_secs(30),
        reconnect_max: Duration::from_secs(60),
        primary_recheck: Duration::from_secs(60),
        age_identity: None,
        auto_unlock: true,
        shutdown,
    };
    (cfg, shutdown_tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn encrypted_wallet_unlock_lock_cycle() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();

    // Build a passphrase-encrypted, account-initialized regtest wallet offline.
    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_passphrase(
        &wd,
        Passphrase::from("pw".to_string()),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
    )
    .unwrap();
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    let (cfg, _shutdown_tx) = offline_actor_cfg("enc", wd);
    let (handle, _task) = actor::spawn(cfg).await.unwrap();

    // Wrong passphrase -> -14.
    let e = handle
        .unlock(Passphrase::from("wrong".to_string()), 60)
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::RPC_WALLET_PASSPHRASE_INCORRECT, "{e}");

    // Correct passphrase unlocks; status reports a future relock time.
    handle
        .unlock(Passphrase::from("pw".to_string()), 60)
        .await
        .unwrap();
    assert!(
        handle.status().unlocked_until.unwrap_or(0) > 0,
        "unlocked_until should be set after unlock"
    );

    // walletlock relocks; unlocked_until drops to 0.
    handle.lock().await.unwrap();
    assert_eq!(handle.status().unlocked_until, Some(0));

    // A zero timeout relocks immediately (Bitcoin allows timeout == 0).
    handle
        .unlock(Passphrase::from("pw".to_string()), 0)
        .await
        .unwrap();
    assert_eq!(handle.status().unlocked_until, Some(0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn unencrypted_wallet_rejects_passphrase_rpcs() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();

    // An identity-encrypted (unencrypted, in Bitcoin terms) wallet.
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_mnemonic(
        &wd,
        std::iter::once(&recipient as &dyn age::Recipient),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
    )
    .unwrap();
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    let (cfg, _shutdown_tx) = offline_actor_cfg("plain", wd);
    let (handle, _task) = actor::spawn(cfg).await.unwrap();

    // walletpassphrase / walletlock on an unencrypted wallet -> -15 (matches bitcoind).
    let e = handle
        .unlock(Passphrase::from("pw".to_string()), 60)
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::RPC_WALLET_WRONG_ENC_STATE, "{e}");
    let e = handle.lock().await.unwrap_err();
    assert_eq!(e.code, codes::RPC_WALLET_WRONG_ENC_STATE, "{e}");

    // ...and it reports no unlock deadline at all.
    assert_eq!(handle.status().unlocked_until, None);
}
