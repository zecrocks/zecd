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
use crate::wallet::{labels, open, read};

/// The committed testnet test mnemonic (valueless TAZ wallet); reused here purely as a
/// deterministic seed source for a throwaway regtest wallet.
const TEST_PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
    midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
    moment stage";

fn test_seed() -> SecretVec<u8> {
    let mut seed = <Mnemonic<English>>::from_phrase(TEST_PHRASE)
        .unwrap()
        .to_seed("");
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
    let bal = read::balance(net, wallet_dir, Default::default()).expect("balance");
    assert_eq!(bal.total_spendable, 0);
    assert_eq!(bal.pending, 0);
    assert!(read::list_unspent(net, wallet_dir)
        .expect("listunspent")
        .is_empty());
    // The transaction queries (v_transactions joined with blocks + raw transactions for
    // blockhash / blockindex / created_time) run against the real librustzcash schema.
    assert!(read::list_transactions(wallet_dir)
        .expect("listtransactions")
        .is_empty());
    assert!(read::get_transaction(wallet_dir, &"ab".repeat(32))
        .expect("gettransaction")
        .is_none());
    assert!(!read::tx_exists(wallet_dir, &"ab".repeat(32)));
    assert!(read::first_scanned_block(wallet_dir)
        .expect("first_scanned_block")
        .is_none());
    // First-seen side table: record once, ignore duplicates, read back.
    labels::record_first_seen(wallet_dir, &"cd".repeat(32), 1_700_000_000).expect("record");
    labels::record_first_seen(wallet_dir, &"cd".repeat(32), 1_900_000_000).expect("record dup");
    assert_eq!(
        labels::first_seen(wallet_dir, &"cd".repeat(32)).expect("first_seen"),
        Some(1_700_000_000)
    );
    assert_eq!(
        labels::first_seen_all(wallet_dir)
            .expect("first_seen_all")
            .len(),
        1
    );

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

/// The tparty address-derivation invariants, offline on regtest:
///
/// 1. tparty's `getnewaddress` yields base58 transparent addresses (`tm…` on regtest) and a
///    fresh one per call;
/// 2. **no collisions with zecd, even on the same seed and account**: zecd's addresses are
///    Orchard-only unified addresses carrying *no* transparent receiver, so the two address
///    sets are disjoint by receiver type - a deposit address handed out by tparty can never
///    equal an invoice address handed out by zecd;
/// 3. the read helpers see the t-addresses as the wallet's own.
#[test]
fn tparty_addresses_never_collide_with_zecd() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = dir.path();

    let mut db = open::init_dbs_with(net, wallet_dir, Some(100)).expect("init regtest dbs");
    let (account_id, _) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    db.update_chain_tip(BlockHeight::from_u32(1))
        .expect("set tip");

    // zecd-style addresses: Orchard-only UAs of this same account.
    let mut zecd_addrs = std::collections::BTreeSet::new();
    for _ in 0..5 {
        let (ua, _) = db
            .get_next_available_address(account_id, UnifiedAddressRequest::ORCHARD)
            .expect("address query")
            .expect("address available");
        assert!(
            ua.transparent().is_none(),
            "zecd's Orchard-only UA must carry no transparent receiver"
        );
        zecd_addrs.insert(ua.encode(&net));
    }

    // tparty-style addresses from the SAME account: transparent P2PKH receivers.
    let mut taddrs = std::collections::BTreeSet::new();
    for _ in 0..5 {
        let addr = crate::wallet::actor::next_transparent_address(&mut db, account_id, net)
            .expect("derive transparent address");
        assert!(
            addr.starts_with("tm"),
            "regtest transparent P2PKH addresses are base58 tm…, got {addr}"
        );
        assert!(taddrs.insert(addr), "every call yields a fresh address");
    }

    // The collision guarantee: the two sets are disjoint (different receiver types - a
    // base58 t-address can never equal a bech32m unified address).
    assert!(
        zecd_addrs.is_disjoint(&taddrs),
        "tparty and zecd address sets must never intersect"
    );

    drop(db);

    // The read helpers know the t-addresses as the wallet's own.
    let listed = read::transparent_addresses(net, wallet_dir);
    for addr in &taddrs {
        assert!(listed.contains(addr), "transparent_addresses lists {addr}");
        assert!(read::is_mine(net, wallet_dir, addr), "{addr} is mine");
    }
    // Unshielded balances on a fresh wallet are zero but well-formed.
    let (spendable, pending) =
        read::transparent_balance(net, wallet_dir, 1).expect("transparent balance");
    assert_eq!((spendable, pending), (0, 0));
    assert!(read::list_transparent_unspent(net, wallet_dir)
        .expect("list transparent unspent")
        .is_empty());
}

/// The transparent gap limit surfaces as Bitcoin Core's -12 (keypool ran out). The unused
/// window includes the account's default (index-0) address exposed at creation, so a gap
/// limit of N yields N-1 fresh `getnewaddress` calls before the refusal. (Deposits to the
/// earlier addresses would slide the window forward; none exist in this offline test.)
#[test]
fn transparent_gap_limit_maps_to_keypool_ran_out() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();

    let mut db = open::init_dbs_with(net, dir.path(), Some(3)).expect("init regtest dbs");
    let (account_id, _) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    db.update_chain_tip(BlockHeight::from_u32(1))
        .expect("set tip");

    for _ in 0..2 {
        crate::wallet::actor::next_transparent_address(&mut db, account_id, net)
            .expect("addresses within the gap limit");
    }
    let err = crate::wallet::actor::next_transparent_address(&mut db, account_id, net)
        .expect_err("the gap limit refuses the next unused address");
    assert_eq!(err.code, codes::RPC_WALLET_KEYPOOL_RAN_OUT, "{err}");
}

/// Received transparent outputs must surface in history under the **t-address** the payer
/// actually paid, not the address row's unified encoding (`v_tx_outputs.to_address` carries
/// the latter - the gap that originally broke `getreceivedbyaddress` in the tparty e2e).
/// Offline: store a fabricated deposit UTXO for a derived t-address and read history back.
#[test]
fn transparent_receive_reports_the_t_address() {
    use zcash_client_backend::wallet::WalletTransparentOutput;
    use zcash_keys::encoding::AddressCodec as _;
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::address::TransparentAddress;
    use zcash_transparent::bundle::{OutPoint, TxOut};

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = dir.path();

    let mut db = open::init_dbs_with(net, wallet_dir, Some(100)).expect("init regtest dbs");
    let (account_id, _) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    db.update_chain_tip(BlockHeight::from_u32(10))
        .expect("set tip");

    let taddr_str = crate::wallet::actor::next_transparent_address(&mut db, account_id, net)
        .expect("derive transparent address");
    let taddr = TransparentAddress::decode(&net, &taddr_str).expect("decode own t-address");

    // A 1-ZEC deposit to the t-address, "mined" at height 5 - what refresh_transparent_utxos
    // stores when lightwalletd reports the UTXO.
    let output = WalletTransparentOutput::from_parts(
        OutPoint::new([9u8; 32], 0),
        TxOut::new(
            Zatoshis::from_u64(100_000_000).unwrap(),
            taddr.script().into(),
        ),
        Some(BlockHeight::from_u32(5)),
    )
    .expect("valid P2PKH output");
    db.put_received_transparent_utxo(&output)
        .expect("store the deposit UTXO");
    drop(db);

    // History reports the receive under the bare t-address.
    let txs = read::list_transactions(wallet_dir).expect("list transactions");
    let receive = txs
        .iter()
        .flat_map(|t| &t.outputs)
        .find(|o| o.to_account.is_some() && !o.is_change)
        .expect("the deposit output is in history");
    assert_eq!(receive.pool, 0, "transparent pool");
    assert_eq!(receive.value, 100_000_000);
    assert_eq!(
        receive.to_address.as_deref(),
        Some(taddr_str.as_str()),
        "received transparent outputs report the paid t-address"
    );

    // The unshielded balance sees the (confirmed) deposit, and listunspent lists the outpoint.
    let (spendable, _pending) =
        read::transparent_balance(net, wallet_dir, 1).expect("transparent balance");
    assert_eq!(spendable, 100_000_000);
    let utxos = read::list_transparent_unspent(net, wallet_dir).expect("list unspent");
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].address, taddr_str);
    assert_eq!(utxos[0].value, 100_000_000);
    assert_eq!(utxos[0].mined_height, Some(5));
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
        auto_shield: None,
        gap_limit: None,
        confirmations_policy: Default::default(),
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
