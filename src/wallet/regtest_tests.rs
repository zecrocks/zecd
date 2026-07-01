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
use zcash_client_backend::data_api::{AccountBirthday, WalletRead as _, WalletWrite};
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
    let mut seed = <Mnemonic<English>>::from_phrase(TEST_PHRASE)
        .unwrap()
        .to_seed("");
    let secret = SecretVec::new(seed.to_vec());
    seed.zeroize();
    secret
}

/// A second, unrelated seed (standard BIP-39 "abandon…art" test vector) for "foreign wallet"
/// negative cases - its addresses must never be attributed to [`test_seed`]'s account.
const FOREIGN_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon art";

fn foreign_seed() -> SecretVec<u8> {
    let mut seed = <Mnemonic<English>>::from_phrase(FOREIGN_PHRASE)
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

/// The Phase-1 bootstrap rebuild is deterministic: recreating the account from the same seed
/// (what the actor does on an empty data directory) reproduces the *same* wallet - identical
/// UFVK and identical addresses at every diversifier index. This is the offline proof that a
/// rebuilt `data.sqlite` is the same wallet; the live funded-spend-after-rebuild is exercised
/// by the regtest CI tier.
#[test]
fn bootstrap_rebuild_reproduces_the_same_account() {
    use zcash_client_backend::data_api::Account as _;

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path();
    let indexes = [1u32, 77, 4242];

    // The original account, with its UFVK and a few diversified addresses recorded.
    let mut db = open::init_dbs(net, wd).expect("init dbs");
    let (account, _usk) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create account");
    let ufvk_before = db
        .get_account(account)
        .unwrap()
        .unwrap()
        .ufvk()
        .unwrap()
        .encode(&net);
    let addrs_before: Vec<String> = indexes
        .iter()
        .map(|&i| {
            let j = zip32::DiversifierIndex::from(i);
            db.get_address_for_index(account, j, UnifiedAddressRequest::ORCHARD)
                .unwrap()
                .unwrap()
                .encode(&net)
        })
        .collect();
    drop(db);

    // Wipe data.sqlite and its WAL sidecars - the empty-data-directory bootstrap case.
    let data = open::data_db_path(wd);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{}", data.display(), suffix));
    }

    // Rebuild from the same seed (what the actor's bootstrap does, minus the network-fetched
    // birthday tree state) and confirm it is byte-for-byte the same wallet.
    let mut db2 = open::init_dbs(net, wd).expect("re-init dbs");
    let (account2, _) = db2
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("recreate account");
    let ufvk_after = db2
        .get_account(account2)
        .unwrap()
        .unwrap()
        .ufvk()
        .unwrap()
        .encode(&net);
    assert_eq!(ufvk_after, ufvk_before, "rebuilt account has the same UFVK");
    for (&i, before) in indexes.iter().zip(&addrs_before) {
        let j = zip32::DiversifierIndex::from(i);
        let after = db2
            .get_address_for_index(account2, j, UnifiedAddressRequest::ORCHARD)
            .unwrap()
            .unwrap()
            .encode(&net);
        assert_eq!(&after, before, "same address at index {i} after rebuild");
    }
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
    assert!(read::get_transaction(net, wallet_dir, &"ab".repeat(32))
        .expect("gettransaction")
        .is_none());
    assert!(!read::tx_exists(wallet_dir, &"ab".repeat(32)));
    assert!(read::first_scanned_block(wallet_dir)
        .expect("first_scanned_block")
        .is_none());

    // 3b. Column-existence guards for the remaining raw queries that reach into librustzcash's
    // internal tables (no public API covers them). The wallet is empty, so each returns nothing -
    // but `prepare()` validates every referenced column against the real schema, so a
    // `zcash_client_sqlite` bump that renames a column we depend on fails loudly here (offline)
    // instead of silently at runtime. Together with the `list_unspent`/`list_transactions`/
    // `get_transaction` calls above, this covers every internal column zecd reads.
    assert_eq!(read::tx_count(wallet_dir).expect("tx_count"), 0);
    assert!(read::unmined_raw_txs(wallet_dir, 1)
        .expect("unmined_raw_txs")
        .is_empty());
    // received_tx_records also exercises transparent_receiver_map (the `addresses` table); both
    // the unfiltered and address-filtered shapes run.
    assert!(read::received_tx_records(wallet_dir, None)
        .expect("received_tx_records")
        .is_empty());
    assert!(read::received_tx_records(wallet_dir, Some(addr.as_str()))
        .expect("received_tx_records filtered")
        .is_empty());
    // The `blocks`-table queries (no public API exposes block time / a reverse hash lookup).
    assert!(read::block_info_at(wallet_dir, 1)
        .expect("block_info_at")
        .is_none());
    assert!(read::median_time_past(wallet_dir, 1)
        .expect("median_time_past")
        .is_none());
    assert!(read::block_height_by_hash(wallet_dir, &"ab".repeat(32))
        .expect("block_height_by_hash")
        .is_none());

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

/// `is_mine` must recognize an address the wallet's account *can derive* even when that address
/// was never recorded in the `addresses` table - the case a stateless (or any) from-seed restore
/// leaves behind for an address that was issued but never funded (so the chain scan never re-added
/// it). This exercises the cryptographic-attribution path (`UnifiedIncomingViewingKey::
/// decrypt_diversifiers`) across **both** shielded pools, and confirms a foreign wallet's
/// addresses are rejected.
#[test]
fn is_mine_attributes_unrecorded_addresses_via_viewing_key() {
    use zcash_client_backend::data_api::Account as _;
    use zcash_keys::address::Address;
    use zip32::DiversifierIndex;

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = dir.path();

    let mut db = open::init_dbs(net, wallet_dir).expect("init dbs");
    let (account_id, _usk) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create account");
    db.update_chain_tip(BlockHeight::from_u32(1)).unwrap();

    // The account's UFVK -> UIVK. Deriving addresses straight from the key never touches the
    // `addresses` table, so they stay unrecorded - exactly the post-restore "forgotten address"
    // shape. (`to_unified_incoming_viewing_key` returns an owned key, so the borrow of `account`
    // ends here, leaving `db` free for the writer call below.)
    let account = db.get_account(account_id).unwrap().unwrap();
    let uivk = account.ufvk().unwrap().to_unified_incoming_viewing_key();

    // A recorded address (writer path), to prove the cheap exact-match layer still works.
    let (recorded_ua, _) = db
        .get_next_available_address(account_id, UnifiedAddressRequest::ORCHARD)
        .unwrap()
        .unwrap();
    let recorded = recorded_ua.encode(&net);
    drop(db);

    // A far diversifier index: `getnewaddress` picks clock-derived indices (~unix time), so a
    // small fixed index is one the wallet would never have auto-recorded.
    let far = DiversifierIndex::from(1_000_007u32);

    // --- Orchard pool: an Orchard-only UA at the far index ---
    let orchard_addr = uivk
        .address(far, UnifiedAddressRequest::ORCHARD)
        .expect("derive Orchard UA")
        .encode(&net);
    assert!(
        !read::all_addresses(net, wallet_dir).contains(&orchard_addr),
        "the far-index address must not be pre-recorded, so only the crypto path can match"
    );
    assert!(
        read::is_mine(net, wallet_dir, &orchard_addr),
        "own Orchard UA must be ismine via viewing-key attribution"
    );

    // --- Sapling pool: take an all-pools UA's Sapling receiver and test it as a bare address,
    //     so the match can only come from the Sapling ivk path ---
    let all_ua = uivk
        .address(far, UnifiedAddressRequest::ALLOW_ALL)
        .expect("derive all-pools UA");
    let sapling_addr =
        Address::Sapling(*all_ua.sapling().expect("UFVK has a Sapling receiver")).encode(&net);
    assert!(
        read::is_mine(net, wallet_dir, &sapling_addr),
        "own bare Sapling address must be ismine via viewing-key attribution"
    );

    // --- Recorded-address fast path still resolves ---
    assert!(
        read::is_mine(net, wallet_dir, &recorded),
        "a recorded address stays ismine"
    );

    // --- A foreign wallet's addresses are NOT ismine (both pools) ---
    let fdir = tempfile::tempdir().unwrap();
    let mut fdb = open::init_dbs(net, fdir.path()).unwrap();
    let (faccount_id, _) = fdb
        .create_account("foreign", &foreign_seed(), &genesis_birthday(), None)
        .unwrap();
    let faccount = fdb.get_account(faccount_id).unwrap().unwrap();
    let fuivk = faccount.ufvk().unwrap().to_unified_incoming_viewing_key();
    drop(fdb);

    let foreign_orchard = fuivk
        .address(far, UnifiedAddressRequest::ORCHARD)
        .unwrap()
        .encode(&net);
    assert!(
        !read::is_mine(net, wallet_dir, &foreign_orchard),
        "a foreign Orchard UA must not be ismine"
    );
    let foreign_all = fuivk
        .address(far, UnifiedAddressRequest::ALLOW_ALL)
        .unwrap();
    let foreign_sapling = Address::Sapling(*foreign_all.sapling().unwrap()).encode(&net);
    assert!(
        !read::is_mine(net, wallet_dir, &foreign_sapling),
        "a foreign bare Sapling address must not be ismine"
    );
}

/// THREAT MODEL - the "unexpected receiver" UA splice (a malicious `is_mine` attempt). An attacker
/// who learns one of the wallet's receivers can craft a unified address that pairs *their* receiver
/// in one pool with the *victim's* receiver in another, e.g. `{ attacker Orchard, victim Sapling }`.
/// A "one receiver is mine ⇒ mine" rule would report `ismine: true`, yet a sender resolves the UA
/// to its most-preferred pool (ZIP-316: Orchard first) and pays the attacker - and a sender that
/// only supports the pool holding the *foreign* receiver pays the attacker regardless of order. So
/// `is_mine` must reject any multi-receiver UA that is not wholly the wallet's at one index. This
/// test builds both spliced orientations and asserts they are NOT ismine, while a genuinely
/// own all-pools UA (and the wallet's own single-pool receivers) still is.
#[test]
fn is_mine_rejects_spliced_unified_address_with_foreign_receiver() {
    use zcash_client_backend::data_api::Account as _;
    use zcash_keys::address::{Address, UnifiedAddress};
    use zip32::DiversifierIndex;

    let net = network::regtest();

    // Victim wallet.
    let dir = tempfile::tempdir().unwrap();
    let wallet_dir = dir.path();
    let mut db = open::init_dbs(net, wallet_dir).expect("init dbs");
    let (account_id, _usk) = db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create account");
    db.update_chain_tip(BlockHeight::from_u32(1)).unwrap();
    let account = db.get_account(account_id).unwrap().unwrap();
    let uivk = account.ufvk().unwrap().to_unified_incoming_viewing_key();
    drop(db);

    // Attacker wallet (a different seed = different keys).
    let fdir = tempfile::tempdir().unwrap();
    let mut fdb = open::init_dbs(net, fdir.path()).unwrap();
    let (faccount_id, _) = fdb
        .create_account("attacker", &foreign_seed(), &genesis_birthday(), None)
        .unwrap();
    let faccount = fdb.get_account(faccount_id).unwrap().unwrap();
    let fuivk = faccount.ufvk().unwrap().to_unified_incoming_viewing_key();
    drop(fdb);

    let far = DiversifierIndex::from(1_000_007u32);
    let mine_all = uivk.address(far, UnifiedAddressRequest::ALLOW_ALL).unwrap();
    let attacker_all = fuivk
        .address(far, UnifiedAddressRequest::ALLOW_ALL)
        .unwrap();

    // Sanity: a genuinely own all-pools UA is still ismine under the consistency-aware rule.
    assert!(
        read::is_mine(net, wallet_dir, &mine_all.encode(&net)),
        "the wallet's own all-pools UA must stay ismine"
    );

    // Splice A: attacker's Orchard receiver + the victim's Sapling receiver. A sender prefers
    // Orchard, so funds would go to the attacker - this must NOT be ismine.
    let splice_a = UnifiedAddress::from_receivers(
        attacker_all.orchard().cloned(),
        mine_all.sapling().cloned(),
        None,
    )
    .expect("build spliced UA")
    .encode(&net);
    // The victim's Sapling receiver alone IS theirs - proving the splice would fool a naive
    // "any receiver mine" rule.
    assert!(
        read::is_mine(
            net,
            wallet_dir,
            &Address::Sapling(*mine_all.sapling().unwrap()).encode(&net)
        ),
        "precondition: the victim's bare Sapling receiver is genuinely theirs"
    );
    assert!(
        !read::is_mine(net, wallet_dir, &splice_a),
        "a UA pairing the attacker's Orchard receiver with the victim's Sapling receiver must NOT \
         be ismine (a sender prefers Orchard and pays the attacker)"
    );

    // Splice B: the victim's Orchard receiver + attacker's Sapling receiver. Even with the
    // victim's receiver in the preferred pool, a Sapling-only sender pays the attacker - reject.
    let splice_b = UnifiedAddress::from_receivers(
        mine_all.orchard().cloned(),
        attacker_all.sapling().cloned(),
        None,
    )
    .expect("build spliced UA")
    .encode(&net);
    assert!(
        !read::is_mine(net, wallet_dir, &splice_b),
        "a UA pairing the victim's Orchard receiver with the attacker's Sapling receiver must NOT \
         be ismine (a Sapling-only sender pays the attacker)"
    );

    // The classifier agrees: both splices are Inconsistent (a foreign receiver mixed in).
    assert!(matches!(
        read::classify_unified_receivers(net, wallet_dir, &splice_a),
        read::UaReceivers::Inconsistent(_)
    ));
    assert!(matches!(
        read::classify_unified_receivers(net, wallet_dir, &splice_b),
        read::UaReceivers::Inconsistent(_)
    ));
}

/// The watch-only (UFVK) pairing guarantee, offline on regtest:
///
/// 1. a wallet built from the spending wallet's exported UFVK (`init --ufvk` ≙
///    `import_account_ufvk` + `AccountPurpose::ViewOnly`) derives addresses from **the same
///    key material**: at any given diversifier index both wallets produce the identical
///    address, so an invoice handed out by the watch-only instance is a diversified address
///    of the account the spending wallet controls (note detection is IVK-based and
///    diversifier-independent). NB: equality is asserted at *fixed* indexes via
///    `get_address_for_index` - `get_next_available_address` picks its index from the wall
///    clock (`zcash_client_sqlite`'s time-based shielded diversifiers), so two wallets'
///    `getnewaddress` results only coincide within the same second;
/// 2. the imported account carries no key derivation (the actor's "can this wallet spend?"
///    signal) and reports the ViewOnly purpose (the actor's `watch_only` signal);
/// 3. the read helpers (`is_mine`, balances) work against the watch-only DB.
#[test]
fn watch_only_ufvk_wallet_pairs_with_spending_wallet() {
    use zcash_client_backend::data_api::{Account as _, AccountPurpose, AccountSource};
    use zcash_keys::keys::UnifiedSpendingKey;

    let net = network::regtest();

    // The spending wallet, and the UFVK an operator would get from `export-ufvk`.
    let spend_dir = tempfile::tempdir().unwrap();
    let mut spend_db = open::init_dbs(net, spend_dir.path()).expect("init spending dbs");
    let (spend_account, _) = spend_db
        .create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create spending account");
    spend_db
        .update_chain_tip(BlockHeight::from_u32(1))
        .expect("set tip");
    let ufvk = {
        use secrecy::ExposeSecret as _;
        let seed = test_seed();
        UnifiedSpendingKey::from_seed(
            &net,
            seed.expose_secret(),
            zip32::AccountId::try_from(0u32).unwrap(),
        )
        .expect("derive USK")
        .to_unified_full_viewing_key()
    };
    // What export-ufvk prints is the encoding of the account's stored UFVK; both must agree.
    let exported = spend_db
        .get_account(spend_account)
        .expect("read spending account")
        .expect("spending account exists")
        .ufvk()
        .expect("spending account has a UFVK")
        .encode(&net);
    assert_eq!(
        exported,
        ufvk.encode(&net),
        "exported UFVK matches the seed-derived one"
    );

    // The watch-only wallet: same UFVK, fresh DB, ViewOnly purpose (the init --ufvk path).
    let watch_dir = tempfile::tempdir().unwrap();
    let mut watch_db = open::init_dbs(net, watch_dir.path()).expect("init watch-only dbs");
    let account = watch_db
        .import_account_ufvk(
            "watch",
            &ufvk,
            &genesis_birthday(),
            AccountPurpose::ViewOnly,
            None,
        )
        .expect("import the UFVK view-only");
    let watch_account = account.id();
    assert!(
        account.source().key_derivation().is_none(),
        "a view-only import carries no spending derivation"
    );
    assert!(
        matches!(
            account.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::ViewOnly,
                ..
            }
        ),
        "the imported account reports the ViewOnly purpose"
    );
    watch_db
        .update_chain_tip(BlockHeight::from_u32(1))
        .expect("set tip");

    // Address determinism: at any fixed diversifier index, both wallets derive the
    // identical Orchard UA (same UFVK → same address space). Clock-independent, unlike
    // `get_next_available_address` (see the test doc comment). Index 0 is skipped: it is
    // already exposed as each account's default address with a different receiver set, and
    // librustzcash refuses to expose a second UA at a used index (DiversifierIndexReuse).
    for index in [1u32, 77, 4242, 1_000_000] {
        let j = zip32::DiversifierIndex::from(index);
        let spend_ua = spend_db
            .get_address_for_index(spend_account, j, UnifiedAddressRequest::ORCHARD)
            .expect("spending address query")
            .expect("index is valid for orchard");
        let watch_ua = watch_db
            .get_address_for_index(watch_account, j, UnifiedAddressRequest::ORCHARD)
            .expect("watch-only address query")
            .expect("a view-only account still derives addresses");
        assert_eq!(
            watch_ua.encode(&net),
            spend_ua.encode(&net),
            "watch-only and spending wallets derive the same address at index {index}"
        );
    }

    // ...and the watch-only wallet's `getnewaddress` path works from the viewing key alone.
    let (watch_ua, _) = watch_db
        .get_next_available_address(watch_account, UnifiedAddressRequest::ORCHARD)
        .expect("watch-only address query")
        .expect("a view-only account derives fresh addresses");
    let addr = watch_ua.encode(&net);
    assert!(addr.starts_with("uregtest1"), "{addr}");

    drop(spend_db);
    drop(watch_db);

    // The read paths the RPC handlers use work against the watch-only DB.
    assert!(
        read::is_mine(net, watch_dir.path(), &addr),
        "the watch-only wallet recognises its own address"
    );
    let bal = read::balance(net, watch_dir.path(), Default::default()).expect("balance");
    assert_eq!((bal.total_spendable, bal.pending), (0, 0));
}

// --- Actor-level encryption plumbing (offline, but `#[ignore]`d because `actor::spawn` loads the
// bundled Sapling prover, which is slow). Run with `cargo test -- --include-ignored`. The actor
// serves walletpassphrase/walletlock commands even while its lightwalletd connection is failing,
// so a dead server endpoint is fine here. ---

use std::time::Duration;

use crate::backend;
use crate::error::codes;
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
    let keys_path = crate::wallet::store::keys_path(&wallet_dir);
    let cfg = ActorConfig {
        name: name.to_string(),
        network: net,
        wallet_dir,
        keys_path,
        server: backend::resolve("127.0.0.1:1", net).unwrap(),
        sync_interval: Duration::from_secs(60),
        rebroadcast_interval: Duration::from_secs(60),
        connect_timeout: Duration::from_millis(150),
        reconnect_base: Duration::from_secs(30),
        reconnect_max: Duration::from_secs(60),
        age_identity: None,
        auto_unlock: true,
        bootstrap: true,
        confirmations_policy: Default::default(),
        orchard_action_limit: crate::config::DEFAULT_ORCHARD_ACTION_LIMIT,
        // Offline test: the actor never sends, so skip building the (expensive) proving key.
        orchard_keys: None,
        pipeline_proving: false,
        enabled_pools: crate::pools::PoolSet::single(crate::pools::Pool::Orchard),
        default_receivers: crate::pools::PoolSet::single(crate::pools::Pool::Orchard),
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
        &crate::wallet::store::keys_path(&wd),
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
        &crate::wallet::store::keys_path(&wd),
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

/// A watch-only wallet through the actor: addresses still derive, but spending and
/// encryption commands refuse with Bitcoin Core's -4 (Private keys are disabled), and the
/// published status carries `watch_only` (→ `getwalletinfo.private_keys_enabled: false`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn watch_only_wallet_disables_spending_rpcs() {
    use secrecy::ExposeSecret as _;
    use zcash_client_backend::data_api::AccountPurpose;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::value::Zatoshis;
    use zip321::{Payment, TransactionRequest};

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();

    // Build the watch-only wallet exactly as `init --ufvk` does: a seedless keys.toml plus a
    // view-only UFVK import (the UFVK derived from the committed test seed).
    WalletStore::init_view_only(
        &crate::wallet::store::keys_path(&wd),
        BlockHeight::from_u32(1),
        net,
    )
    .unwrap();
    let ufvk = {
        let seed = test_seed();
        UnifiedSpendingKey::from_seed(
            &net,
            seed.expose_secret(),
            zip32::AccountId::try_from(0u32).unwrap(),
        )
        .unwrap()
        .to_unified_full_viewing_key()
    };
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.import_account_ufvk(
        "watch",
        &ufvk,
        &genesis_birthday(),
        AccountPurpose::ViewOnly,
        None,
    )
    .unwrap();
    // Address generation consults the chain height; the actor is offline here (dead
    // upstream), so record a tip directly like the other offline tests.
    db.update_chain_tip(BlockHeight::from_u32(1)).unwrap();
    drop(db);

    let (cfg, _shutdown_tx) = offline_actor_cfg("watch", wd);
    let (handle, _task) = actor::spawn(cfg).await.unwrap();

    // Address generation works from the viewing key alone. (Round-tripping a command also
    // guarantees the actor has published its first status snapshot, which `spawn` itself
    // does not wait for.)
    let addr = handle.get_new_address(None).await.unwrap();
    assert!(addr.starts_with("uregtest1"), "{addr}");

    // The status feed marks the wallet watch-only (not encrypted - there is nothing to lock).
    let st = handle.status();
    assert!(st.watch_only, "status must report watch_only");
    assert!(!st.encrypted);
    assert_eq!(st.unlocked_until, None);

    // sendtoaddress/sendmany surface Bitcoin Core's -4 before touching keys or the network.
    let payment = Payment::new(
        zcash_address::ZcashAddress::try_from_encoded(&addr).unwrap(),
        Some(Zatoshis::from_u64(10_000).unwrap()),
        None,
        None,
        None,
        vec![],
    )
    .unwrap();
    let e = handle
        .send(
            TransactionRequest::new(vec![payment]).unwrap(),
            None,
            crate::config::SendPrivacy::AllowRevealedRecipients,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::RPC_WALLET_ERROR, "{e}");
    assert!(
        e.message.contains("Private keys are disabled"),
        "Bitcoin Core's watch-only refusal: {e}"
    );

    // The passphrase RPCs see an unencrypted wallet (-15), like bitcoind without privkeys.
    let e = handle
        .unlock(Passphrase::from("pw".to_string()), 60)
        .await
        .unwrap_err();
    assert_eq!(e.code, codes::RPC_WALLET_WRONG_ENC_STATE, "{e}");
}
