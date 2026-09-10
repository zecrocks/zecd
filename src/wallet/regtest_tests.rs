//! Offline wallet-database tests, run against a real `WalletDb` on a regtest network.
//!
//! librustzcash's funded test harness (`zcash_client_sqlite`'s `TestDbFactory`) is crate-private,
//! so an actual *funded* note cannot be materialised here; funded receive/spend lives in the
//! regtest tier (`regtest-harness/`, whose funder is a released zecd that shields regtest
//! coinbase with `z_shieldcoinbase`) and, for the public network, in the manual testnet flow.
//! What this file does is everything that needs a real database but no chain, in five groups:
//!
//!  * wallet lifecycle - DB init, account creation, address derivation/encoding, and the
//!    `keys.toml` bootstrap rebuilding the same account;
//!  * `is_mine` attribution, including the viewing-key path for an address that was never
//!    recorded, and the refusal of a spliced UA carrying a foreign receiver;
//!  * multi-account databases - a fleet shard serving many view wallets from one actor, and
//!    the isolation between accounts sharing one DB;
//!  * the actor-level paths that need a spawned actor (encryption plumbing, the account-to-keys
//!    binding checks, watch-only refusals). These are `#[ignore]`d only because `actor::spawn`
//!    loads the bundled prover, which is slow - they are offline like everything else here;
//!  * the differential pins for the hand-written SQL in [`crate::wallet::read`]: each statement
//!    is required to return exactly what the `v_transactions` / `v_tx_outputs` view it replaces
//!    returns, so a `zcash_client_sqlite` bump that changes a view fails here.

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

/// A second, unrelated seed (standard BIP-39 "abandon...art" test vector) for "foreign wallet"
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
    let engine_dir = dir.path();

    // 1. Initialise the wallet DB on regtest and create an account from the seed.
    let mut db = open::init_dbs(net, engine_dir).expect("init regtest dbs");
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

    // 2b. Derive a bare transparent receiver - the `getnewaddress "" "transparent"` path: a UA
    // that requires a p2pkh receiver, from which the transparent receiver is extracted and
    // bare-encoded. Regtest uses testnet's "tm" P2PKH prefix. Generating it also persists the
    // address's `cached_transparent_receiver_address`, which `is_mine` reads (checked below).
    let (tua, _) = db
        .get_next_available_address(account_id, crate::pools::transparent_extraction_request())
        .expect("transparent address query")
        .expect("a transparent address is available for a fresh account");
    let taddr = {
        use zcash_keys::encoding::AddressCodec as _;
        tua.transparent()
            .expect("the derived UA carries a transparent receiver")
            .encode(&net)
    };
    assert!(
        taddr.starts_with("tm"),
        "regtest t-addr should use the tm prefix, got {taddr}"
    );

    // Release the writer connection before the read helpers open their own.
    drop(db);

    // The handed-out transparent address is recognised as the wallet's own.
    assert!(
        read::is_mine(net, engine_dir, read::AccountScope::Any, &taddr),
        "a handed-out transparent receiver should be is_mine, got {taddr}"
    );

    // 3. Read helpers operate on a regtest wallet: empty-but-valid balances and note set.
    let bal = read::balance(net, engine_dir, read::AccountScope::Any, Default::default())
        .expect("balance");
    assert_eq!(bal.total_spendable, 0);
    assert_eq!(bal.pending, 0);
    assert!(read::list_unspent(net, engine_dir, read::AccountScope::Any)
        .expect("listunspent")
        .is_empty());
    // The transaction queries (v_transactions joined with blocks + raw transactions for
    // blockhash / blockindex / created_time) run against the real librustzcash schema.
    assert!(read::list_transactions(engine_dir, read::AccountScope::Any)
        .expect("listtransactions")
        .is_empty());
    assert!(read::get_transaction(
        net,
        engine_dir,
        read::AccountScope::Any,
        &"ab".repeat(32),
        false
    )
    .expect("gettransaction")
    .is_none());
    assert!(!read::tx_exists(engine_dir, &"ab".repeat(32)));
    assert!(read::first_scanned_block(engine_dir)
        .expect("first_scanned_block")
        .is_none());

    // 3b. Column-existence guards for the remaining raw queries that reach into librustzcash's
    // internal tables (no public API covers them). The wallet is empty, so each returns nothing -
    // but `prepare()` validates every referenced column against the real schema, so a
    // `zcash_client_sqlite` bump that renames a column we depend on fails loudly here (offline)
    // instead of silently at runtime. Together with the `list_unspent`/`list_transactions`/
    // `get_transaction` calls above, this covers every internal column zecd reads.
    assert_eq!(
        read::tx_count(engine_dir, read::AccountScope::Any).expect("tx_count"),
        0
    );
    assert!(read::unmined_raw_txs(engine_dir, 1)
        .expect("unmined_raw_txs")
        .is_empty());
    // received_tx_records runs in both the unfiltered and address-filtered shapes.
    assert!(
        read::received_tx_records(engine_dir, read::AccountScope::Any, None)
            .expect("received_tx_records")
            .is_empty()
    );
    assert!(
        read::received_tx_records(engine_dir, read::AccountScope::Any, Some(addr.as_str()))
            .expect("received_tx_records filtered")
            .is_empty()
    );
    // The `blocks`-table queries (no public API exposes block time / a reverse hash lookup).
    assert!(read::block_info_at(engine_dir, 1)
        .expect("block_info_at")
        .is_none());
    assert!(read::median_time_past(engine_dir, 1)
        .expect("median_time_past")
        .is_none());
    assert!(read::block_height_by_hash(engine_dir, &"ab".repeat(32))
        .expect("block_height_by_hash")
        .is_none());

    // 4. is_mine is network-scoped: true for our own regtest address, false for a testnet UA.
    assert!(
        read::is_mine(net, engine_dir, read::AccountScope::Any, &addr),
        "the wallet's own regtest address is mine"
    );
    let testnet_ua = "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";
    assert!(
        !read::is_mine(net, engine_dir, read::AccountScope::Any, testnet_ua),
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
    let engine_dir = dir.path();

    let mut db = open::init_dbs(net, engine_dir).expect("init dbs");
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
        !read::all_addresses(net, engine_dir, read::AccountScope::Any).contains(&orchard_addr),
        "the far-index address must not be pre-recorded, so only the crypto path can match"
    );
    assert!(
        read::is_mine(net, engine_dir, read::AccountScope::Any, &orchard_addr),
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
        read::is_mine(net, engine_dir, read::AccountScope::Any, &sapling_addr),
        "own bare Sapling address must be ismine via viewing-key attribution"
    );

    // --- Recorded-address fast path still resolves ---
    assert!(
        read::is_mine(net, engine_dir, read::AccountScope::Any, &recorded),
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
        !read::is_mine(net, engine_dir, read::AccountScope::Any, &foreign_orchard),
        "a foreign Orchard UA must not be ismine"
    );
    let foreign_all = fuivk
        .address(far, UnifiedAddressRequest::ALLOW_ALL)
        .unwrap();
    let foreign_sapling = Address::Sapling(*foreign_all.sapling().unwrap()).encode(&net);
    assert!(
        !read::is_mine(net, engine_dir, read::AccountScope::Any, &foreign_sapling),
        "a foreign bare Sapling address must not be ismine"
    );
}

/// THREAT MODEL - the "unexpected receiver" UA splice (a malicious `is_mine` attempt). An attacker
/// who learns one of the wallet's receivers can craft a unified address that pairs *their* receiver
/// in one pool with the *victim's* receiver in another, e.g. `{ attacker Orchard, victim Sapling }`.
/// A "one receiver is mine ⇒ mine" rule would report `ismine: true`, yet a sender resolves the UA
/// to its most-preferred pool (ZIP-316: Orchard first) and pays the attacker - and a sender that
/// only supports the pool holding the *foreign* receiver pays the attacker regardless of order. So
/// `is_mine` must reject any multi-receiver UA that is not wholly the wallet's at one index. The
/// same splice also has a **transparent** form - the attacker staples their transparent receiver
/// onto the victim's shielded receiver; since zecd never issues transparent receivers, any UA
/// carrying one can never be the wallet's, and a transparent-only sender pays the attacker. This
/// test builds all three spliced orientations (two shielded, one transparent) and asserts they are
/// NOT ismine, while a genuinely own shielded UA (and the wallet's own single-pool receivers) still
/// is.
#[test]
fn is_mine_rejects_spliced_unified_address_with_foreign_receiver() {
    use zcash_client_backend::data_api::Account as _;
    use zcash_keys::address::{Address, UnifiedAddress};
    use zip32::DiversifierIndex;

    let net = network::regtest();

    // Victim wallet.
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).expect("init dbs");
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
    // The victim's own *shielded* (Sapling + Orchard, no transparent) UA - the shape zecd actually
    // issues (`getnewaddress` builds shielded-only UAs). Its receivers are the raw material for the
    // splices below.
    use zcash_keys::keys::ReceiverRequirement::*;
    let shielded_only = UnifiedAddressRequest::unsafe_custom(Require, Require, Omit);
    let mine_shielded = uivk.address(far, shielded_only).unwrap();
    // The attacker's UA, requested with *all* receivers so it carries a transparent receiver to
    // staple onto the victim's (Splice C).
    let attacker_all = fuivk
        .address(far, UnifiedAddressRequest::ALLOW_ALL)
        .unwrap();

    // Sanity: a genuinely own shielded UA (every receiver ours at one index) is still ismine under
    // the consistency-aware rule.
    assert!(
        read::is_mine(
            net,
            engine_dir,
            read::AccountScope::Any,
            &mine_shielded.encode(&net)
        ),
        "the wallet's own shielded UA must stay ismine"
    );

    // Splice A: attacker's Orchard receiver + the victim's Sapling receiver. A sender prefers
    // Orchard, so funds would go to the attacker - this must NOT be ismine.
    let splice_a = UnifiedAddress::from_receivers(
        attacker_all.orchard().cloned(),
        mine_shielded.sapling().cloned(),
        None,
    )
    .expect("build spliced UA")
    .encode(&net);
    // The victim's Sapling receiver alone IS theirs - proving the splice would fool a naive
    // "any receiver mine" rule.
    assert!(
        read::is_mine(
            net,
            engine_dir,
            read::AccountScope::Any,
            &Address::Sapling(*mine_shielded.sapling().unwrap()).encode(&net)
        ),
        "precondition: the victim's bare Sapling receiver is genuinely theirs"
    );
    assert!(
        !read::is_mine(net, engine_dir, read::AccountScope::Any, &splice_a),
        "a UA pairing the attacker's Orchard receiver with the victim's Sapling receiver must NOT \
         be ismine (a sender prefers Orchard and pays the attacker)"
    );

    // Splice B: the victim's Orchard receiver + attacker's Sapling receiver. Even with the
    // victim's receiver in the preferred pool, a Sapling-only sender pays the attacker - reject.
    let splice_b = UnifiedAddress::from_receivers(
        mine_shielded.orchard().cloned(),
        attacker_all.sapling().cloned(),
        None,
    )
    .expect("build spliced UA")
    .encode(&net);
    assert!(
        !read::is_mine(net, engine_dir, read::AccountScope::Any, &splice_b),
        "a UA pairing the victim's Orchard receiver with the attacker's Sapling receiver must NOT \
         be ismine (a Sapling-only sender pays the attacker)"
    );

    // Splice C: the victim's *own* Orchard receiver + the attacker's *transparent* receiver. Only
    // one shielded receiver is present, so the shielded-consistency check (which counts shielded
    // receivers) never engages - this is the transparent variant of the splice. zecd never issues
    // a transparent receiver, so a UA carrying one can never be an address it handed out, and a
    // transparent-only sender pays the attacker. It must NOT be ismine even though the Orchard
    // receiver alone is genuinely the wallet's.
    let attacker_taddr = attacker_all
        .transparent()
        .cloned()
        .expect("attacker all-pools UA carries a transparent receiver");
    let splice_c = UnifiedAddress::from_receivers(
        mine_shielded.orchard().cloned(),
        None,
        Some(attacker_taddr),
    )
    .expect("build spliced UA with a transparent receiver")
    .encode(&net);
    // Precondition: the victim's bare Orchard receiver alone IS theirs - so only the transparent
    // receiver makes Splice C foreign.
    assert!(
        read::is_mine(
            net,
            engine_dir,
            read::AccountScope::Any,
            &UnifiedAddress::from_receivers(mine_shielded.orchard().cloned(), None, None)
                .unwrap()
                .encode(&net)
        ),
        "precondition: the victim's Orchard-only UA is genuinely theirs"
    );
    assert!(
        !read::is_mine(net, engine_dir, read::AccountScope::Any, &splice_c),
        "a UA stapling the wallet's Orchard receiver to a transparent receiver must NOT be ismine \
         (zecd never issues transparent receivers; a transparent-only sender pays the attacker)"
    );

    // The classifier agrees: both splices are Inconsistent (a foreign receiver mixed in).
    assert!(matches!(
        read::classify_unified_receivers(net, engine_dir, read::AccountScope::Any, &splice_a),
        read::UaReceivers::Inconsistent(_)
    ));
    assert!(matches!(
        read::classify_unified_receivers(net, engine_dir, read::AccountScope::Any, &splice_b),
        read::UaReceivers::Inconsistent(_)
    ));
}

/// A **fleet shard** at scale: many view wallets in one database, one actor, one scan.
///
/// This is the property the whole fleet design rests on, so it is asserted directly rather than
/// inferred: `FLEET_SIZE` unrelated viewing keys are imported into a single `WalletDb`, one
/// `spawn_shard` serves all of them, and every one comes back as its own `/wallet/<name>` handle
/// routed to its own account. The scan itself is shared by construction - `scan_cached_blocks`
/// reads every account's key out of the database and trial-decrypts each block once against the
/// whole set - so what needs guarding is the routing around it: that N wallets do not collapse
/// into one another, and that N wallets do not cost N actors.
///
/// Offline: the accounts are pre-imported at a genesis birthday, so the actor adopts them at spawn
/// and never needs a chain (a member with no account yet is imported on a connected pass instead,
/// which the regtest tier covers). The upstream is a dead port, so the actor runs disconnected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shard_serves_many_view_wallets_from_one_actor() {
    use zcash_keys::keys::UnifiedSpendingKey;

    /// Enough wallets that a per-wallet cost would be obvious, and few enough to stay a fast
    /// offline test. The production bound is `[fleet] shard_size`, not this.
    const FLEET_SIZE: usize = 64;

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let shard_dir = dir.path().to_path_buf();

    // Build `FLEET_SIZE` unrelated wallets and import each as a watch-only account, exactly as
    // the shard's own import path does.
    let mut db = open::init_dbs(net, &shard_dir).unwrap();
    let mut members = Vec::new();
    let mut expected_addresses = Vec::new();
    for i in 0..FLEET_SIZE {
        // Distinct seeds, so any cross-wallet leak shows up as a wrong address rather than a
        // coincidence.
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        let usk = UnifiedSpendingKey::from_seed(&net, &raw, 0u32.try_into().unwrap()).unwrap();
        let ufvk = usk.to_unified_full_viewing_key().encode(&net);
        let member = crate::wallet::shard::ShardMember {
            name: format!("view-{i:04}"),
            ufvk,
            birthday: BlockHeight::from_u32(1),
        };
        let account =
            crate::wallet::shard::import_member(&mut db, &member, &genesis_birthday()).unwrap();
        // The account's default address, which import always derives and exposes. Not a fixed
        // diversifier index: the default index is the seed's first Sapling-valid one, a per-seed
        // value that is 0 for only about half of seeds, so index 0 simply has no address for
        // many of these wallets.
        expected_addresses.push(
            db.list_addresses(account)
                .unwrap()
                .first()
                .expect("import exposes the account's default address")
                .address()
                .encode(&net),
        );
        members.push(member);
    }
    drop(db);

    // One actor for all of them.
    let (mut cfg, _shutdown_tx) = offline_actor_cfg("shard-0000", shard_dir.clone());
    cfg.shard_members = members.clone();
    let (handles, task) = actor::spawn_shard(cfg).await.expect("shard spawns");

    assert_eq!(
        handles.len(),
        FLEET_SIZE,
        "one handle per view wallet, from one actor"
    );

    // Every wallet resolves to its *own* account, and no two share one. This is what makes the
    // scoped reads of the previous commit actually separate the wallets: they all read the same
    // database file.
    let mut seen = std::collections::HashSet::new();
    for (i, handle) in handles.iter().enumerate() {
        assert_eq!(handle.name, format!("view-{i:04}"));
        assert_eq!(
            handle.engine_dir, shard_dir,
            "one database for the whole shard"
        );
        let account = handle
            .account()
            .unwrap_or_else(|| panic!("{} must resolve to an account", handle.name));
        assert!(
            seen.insert(account),
            "{} shares an account with another wallet",
            handle.name
        );
        // The scope reaches the read path, and the read path answers with this wallet's own
        // address - not the shard's first, and not all of them.
        let listed = read::all_addresses(net, &handle.engine_dir, handle.account_scope());
        assert!(
            listed.contains(&expected_addresses[i]),
            "{} must see its own address",
            handle.name
        );
        for (j, other) in expected_addresses.iter().enumerate() {
            assert!(
                i == j || !listed.contains(other),
                "{} must not see view-{j:04}'s address",
                handle.name
            );
        }
    }

    // A watch-only shard holds no spending material, so sends are refused - and, because it can
    // never prove, it also holds none of the bundled Sapling proving parameters (tens of
    // megabytes that would otherwise be resident per shard).
    assert!(
        handles[0].status().watch_only,
        "shard members are watch-only"
    );

    drop(handles);
    task.abort();
}

/// A shard member that has been **placed but not imported** must read nothing - not its shard's
/// everything.
///
/// A member is servable the moment the actor accepts it: `createwallet` returns before the
/// import runs, because importing needs the tree state below the member's birthday and so waits
/// for a connected pass. In that window the wallet has no account of its own, and a wallet with
/// no account scoped to "every account in this database" - which for a shard is its shard-mates'
/// accounts. So the new wallet answered `getbalance`, `listtransactions` and `is_mine` with
/// *other wallets'* money, history and addresses, under its own name.
///
/// Offline, and against the real actor rather than a hand-built handle, because the fix spans
/// three layers that all have to agree: the actor knows it is a shard, the handle carries that,
/// and the read layer honours the scope it implies. The upstream is a dead port, so the pending
/// member stays pending for the life of the test - which is exactly the window under test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shard_member_awaiting_import_reads_nothing_rather_than_its_shards_everything() {
    use zcash_keys::keys::UnifiedSpendingKey;

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let shard_dir = dir.path().to_path_buf();

    let member_of = |i: u64| {
        let mut raw = [0u8; 32];
        raw[..8].copy_from_slice(&i.to_le_bytes());
        let usk = UnifiedSpendingKey::from_seed(&net, &raw, 0u32.try_into().unwrap()).unwrap();
        crate::wallet::shard::ShardMember {
            name: format!("view-{i:04}"),
            ufvk: usk.to_unified_full_viewing_key().encode(&net),
            birthday: BlockHeight::from_u32(1),
        }
    };

    // One member imported (it has an account and an address), one only placed.
    let resident = member_of(1);
    let newcomer = member_of(2);
    let mut db = open::init_dbs(net, &shard_dir).unwrap();
    let resident_account =
        crate::wallet::shard::import_member(&mut db, &resident, &genesis_birthday()).unwrap();
    let resident_address = db
        .list_addresses(resident_account)
        .unwrap()
        .first()
        .expect("import exposes the account's default address")
        .address()
        .encode(&net);
    drop(db);

    let (mut cfg, _shutdown_tx) = offline_actor_cfg("shard-0000", shard_dir.clone());
    cfg.shard_members = vec![resident.clone(), newcomer.clone()];
    let (handles, task) = actor::spawn_shard(cfg).await.expect("shard spawns");

    let handle_named = |name: &str| {
        handles
            .iter()
            .find(|h| h.name == name)
            .unwrap_or_else(|| panic!("a handle for {name}"))
            .clone()
    };
    let resident_handle = handle_named(&resident.name);
    let newcomer_handle = handle_named(&newcomer.name);

    // The premise: one has an account, the other does not - and both read the same database.
    assert_eq!(resident_handle.account(), Some(resident_account));
    assert_eq!(
        newcomer_handle.account(),
        None,
        "the newcomer's import needs a connected upstream, which this test does not give it"
    );
    assert_eq!(resident_handle.engine_dir, newcomer_handle.engine_dir);

    // The fix: no account in a shared database scopes to no account, not to every account.
    assert_eq!(
        newcomer_handle.account_scope(),
        read::AccountScope::NoAccount
    );
    let scope = newcomer_handle.account_scope();
    assert!(
        read::all_addresses(net, &newcomer_handle.engine_dir, scope).is_empty(),
        "a member awaiting import must not list its shard-mates' addresses"
    );
    assert!(
        !read::is_mine(net, &newcomer_handle.engine_dir, scope, &resident_address),
        "nor claim one of them as its own - `is_mine` is what a send's fromaddress is checked \
         against"
    );
    assert_eq!(
        read::tx_count(&newcomer_handle.engine_dir, scope).unwrap(),
        0
    );
    assert!(read::list_transactions(&newcomer_handle.engine_dir, scope)
        .unwrap()
        .is_empty());
    assert!(read::list_unspent(net, &newcomer_handle.engine_dir, scope)
        .unwrap()
        .is_empty());

    // And the resident is undisturbed: the scoping must not cost a wallet its own address.
    assert!(read::is_mine(
        net,
        &resident_handle.engine_dir,
        resident_handle.account_scope(),
        &resident_address
    ));

    drop(handles);
    task.abort();
}

/// Two accounts in **one** wallet database must not see each other through the read helpers.
///
/// This is the shape a fleet shard has: many watch-only wallets sharing one `WalletDb` so the
/// chain is scanned once rather than once per wallet. Every read
/// that reports a wallet's own money, history or addresses therefore carries an
/// [`read::AccountScope`], and this is the guard that the scoping actually holds.
///
/// `is_mine` is the sharp one. It answers "does this wallet own this address?", and `z_sendmany`
/// uses it to decide whether a `fromaddress` names funds the caller may spend from - so an
/// unscoped `is_mine` in a shared database would let one wallet name another wallet's address as
/// its funding source. The other direction matters too: scoping must not make a wallet stop
/// recognizing its *own* addresses.
#[test]
fn accounts_sharing_one_database_do_not_see_each_others_addresses() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).unwrap();

    // Two accounts from unrelated seeds, in one database.
    let (account_a, _) = db
        .create_account("a", &test_seed(), &genesis_birthday(), None)
        .unwrap();
    let (account_b, _) = db
        .create_account("b", &foreign_seed(), &genesis_birthday(), None)
        .unwrap();
    assert_ne!(account_a, account_b);

    let mut address_of = |account| {
        db.get_address_for_index(
            account,
            zip32::DiversifierIndex::from(0u32),
            UnifiedAddressRequest::AllAvailableKeys,
        )
        .unwrap()
        .expect("index 0 derives an address")
        .encode(&net)
    };
    let addr_a = address_of(account_a);
    let addr_b = address_of(account_b);
    assert_ne!(addr_a, addr_b, "unrelated seeds derive different addresses");
    drop(db);

    let scope_a = read::AccountScope::Only(account_a);
    let scope_b = read::AccountScope::Only(account_b);

    // Each account owns its own address and disowns the other's.
    assert!(read::is_mine(net, engine_dir, scope_a, &addr_a));
    assert!(
        !read::is_mine(net, engine_dir, scope_a, &addr_b),
        "account A must not claim account B's address"
    );
    assert!(read::is_mine(net, engine_dir, scope_b, &addr_b));
    assert!(
        !read::is_mine(net, engine_dir, scope_b, &addr_a),
        "account B must not claim account A's address"
    );
    // Unscoped is the pre-fleet behaviour: the database as a whole owns both.
    assert!(read::is_mine(
        net,
        engine_dir,
        read::AccountScope::Any,
        &addr_a
    ));
    assert!(read::is_mine(
        net,
        engine_dir,
        read::AccountScope::Any,
        &addr_b
    ));

    // `all_addresses` backs `getaddressesbyaccount`-style listings, so the same split applies.
    let listed_a = read::all_addresses(net, engine_dir, scope_a);
    let listed_b = read::all_addresses(net, engine_dir, scope_b);
    assert!(listed_a.contains(&addr_a) && !listed_a.contains(&addr_b));
    assert!(listed_b.contains(&addr_b) && !listed_b.contains(&addr_a));
    let listed_all = read::all_addresses(net, engine_dir, read::AccountScope::Any);
    assert!(listed_all.contains(&addr_a) && listed_all.contains(&addr_b));
    assert_eq!(
        listed_all.len(),
        listed_a.len() + listed_b.len(),
        "every listed address belongs to exactly one of the two accounts"
    );

    // Balances and history are empty here (nothing is funded), but they must be empty *per
    // account* rather than by accident - and the scoped queries must run against the real
    // schema, which is what this fixture adds over the hand-built one in `read.rs`.
    for scope in [scope_a, scope_b, read::AccountScope::Any] {
        assert_eq!(read::tx_count(engine_dir, scope).unwrap(), 0);
        assert!(read::list_transactions(engine_dir, scope)
            .unwrap()
            .is_empty());
        assert!(read::list_unspent(net, engine_dir, scope)
            .unwrap()
            .is_empty());
        let bal = read::balance(net, engine_dir, scope, Default::default()).unwrap();
        assert_eq!(bal.total_spendable, 0);
    }

    // `NoAccount` - the scope of a shard member placed but not yet imported - must report
    // nothing, including that it owns *neither* of the addresses in this database. `Any` would
    // claim both, which is exactly the confusion this variant exists to prevent: the wallet is
    // servable in that window, so an unscoped read answers under its name.
    let none = read::AccountScope::NoAccount;
    assert!(!read::is_mine(net, engine_dir, none, &addr_a));
    assert!(!read::is_mine(net, engine_dir, none, &addr_b));
    assert!(read::all_addresses(net, engine_dir, none).is_empty());
    assert_eq!(read::tx_count(engine_dir, none).unwrap(), 0);
    assert!(read::list_transactions(engine_dir, none)
        .unwrap()
        .is_empty());
    assert!(read::list_unspent(net, engine_dir, none)
        .unwrap()
        .is_empty());
    assert_eq!(
        read::balance(net, engine_dir, none, Default::default())
            .unwrap()
            .total_spendable,
        0
    );
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
        read::is_mine(net, watch_dir.path(), read::AccountScope::Any, &addr),
        "the watch-only wallet recognises its own address"
    );
    let bal = read::balance(
        net,
        watch_dir.path(),
        read::AccountScope::Any,
        Default::default(),
    )
    .expect("balance");
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

/// The test seed's index-0 UFVK in its regtest encoding: the pin a real `zecd init` would
/// record for a wallet built from [`test_seed`], required by the actor's startup binding
/// check (keys.toml pin vs the database account).
fn test_pinned_ufvk(net: crate::network::ZNetwork) -> String {
    crate::wallet::binding::seed_ufvk_encoded(
        net,
        &test_seed(),
        zip32::AccountId::try_from(0u32).unwrap(),
    )
    .expect("derive the test seed's UFVK")
}

/// An ActorConfig pointed at a dead local endpoint (connect fails fast; the actor still runs).
/// The returned shutdown sender must be kept alive for the actor's lifetime (dropping it is
/// itself a shutdown signal).
fn offline_actor_cfg(
    name: &str,
    engine_dir: std::path::PathBuf,
) -> (ActorConfig, tokio::sync::watch::Sender<bool>) {
    let (shutdown_tx, shutdown) = tokio::sync::watch::channel(false);
    let net = network::regtest();
    let keys_path = crate::wallet::store::keys_path(&engine_dir);
    let cfg = ActorConfig {
        name: name.to_string(),
        network: net,
        engine_dir,
        keys_path,
        // Explicitly a zebra endpoint: since light mode returned, a bare host:port resolves
        // to lightwalletd. Port 1 never answers - these actors are offline by construction.
        hub: crate::chain::hub::ChainHub::new(
            backend::resolve("zebra://127.0.0.1:1", net).unwrap(),
            Duration::from_millis(150),
        ),
        sync_interval: Duration::from_secs(60),
        rebroadcast_interval: Duration::from_secs(60),
        fetch_memos: true,
        reconnect_base: Duration::from_secs(30),
        reconnect_max: Duration::from_secs(60),
        age_identity: None,
        auto_unlock: true,
        bootstrap: true,
        confirmations_policy: Default::default(),
        spend_limits: crate::config::SpendLimits::new(&crate::config::SpendConfig::default()),
        target_note_count: crate::config::DEFAULT_TARGET_NOTE_COUNT,
        min_split_output_value: crate::config::DEFAULT_MIN_SPLIT_OUTPUT_VALUE,
        // Offline test: the actor never sends, so skip building the (expensive) proving key.
        orchard_keys: None,
        pipeline_proving: false,
        shutdown_drain: std::time::Duration::from_secs(crate::config::DEFAULT_SHUTDOWN_DRAIN_SECS),
        trust_own_transactions: true,
        enabled_pools: crate::pools::ReceiverSet::single(crate::pools::Receiver::Orchard),
        default_receivers: crate::pools::ReceiverSet::single(crate::pools::Receiver::Orchard),
        transparent_enabled: false,
        transparent_default: false,
        transparent_gap_limit: crate::config::DEFAULT_TRANSPARENT_GAP_LIMIT,
        transparent_initial_scan: 0,
        transparent_allow_beyond_recovery_window: true,
        transparent_gap_warn_threshold: 5,
        // A conventional single-wallet actor, not a fleet shard.
        shard_members: Vec::new(),
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
        &test_pinned_ufvk(net),
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
        &test_pinned_ufvk(net),
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
        &test_pinned_ufvk(net),
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
    let addr = handle
        .get_new_address(crate::wallet::ReceiverRequest::Default)
        .await
        .unwrap();
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
            crate::wallet::SendSource::Unspecified,
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

// --- Account-to-keys binding (wallet::binding) through the actor: the startup pin check,
// the legacy-keys.toml backfill, and the unlock-time seed check. Same #[ignore] rationale as
// the encryption tests above (actor::spawn loads the bundled prover). ---

/// A foreign account's UFVK (regtest encoding): what a planted/swapped database would carry.
fn foreign_ufvk(net: crate::network::ZNetwork) -> String {
    crate::wallet::binding::seed_ufvk_encoded(
        net,
        &foreign_seed(),
        zip32::AccountId::try_from(0u32).unwrap(),
    )
    .expect("derive the foreign seed's UFVK")
}

/// Layer 3, mismatch: a wallet whose database account does not match keys.toml's pinned UFVK
/// must refuse to start (fail closed), because serving it would hand out a foreign account's
/// receive addresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn startup_refuses_database_not_matching_pinned_ufvk() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();

    // keys.toml carries the operator's seed and pin, but the database holds a FOREIGN account,
    // as if data.sqlite had been swapped after init.
    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_passphrase(
        &crate::wallet::store::keys_path(&wd),
        Passphrase::from("pw".to_string()),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
        &test_pinned_ufvk(net),
    )
    .unwrap();
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("planted", &foreign_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    let (cfg, _shutdown_tx) = offline_actor_cfg("swapped", wd);
    let err = match actor::spawn(cfg).await {
        Ok(_) => panic!("a swapped database must fail the startup binding check"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("does not match"), "{msg}");
    // Error paths abbreviate the keys: a full UFVK is itself a viewing capability.
    assert!(!msg.contains(&foreign_ufvk(net)), "no full UFVK in errors");
}

/// Layer 3, backfill: a keys.toml from before the pin existed starts normally, gets the pin
/// backfilled trust-on-first-use, and (layer 4) the first unlock verifies the seed against
/// the now-pinned account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn startup_backfills_pin_on_legacy_keys_toml() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();
    let kp = crate::wallet::store::keys_path(&wd);

    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_passphrase(
        &kp,
        Passphrase::from("pw".to_string()),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
        &test_pinned_ufvk(net),
    )
    .unwrap();
    WalletStore::strip_pin_for_tests(&kp); // simulate a pre-pin keys.toml
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    let (cfg, _shutdown_tx) = offline_actor_cfg("legacy", wd);
    let (handle, _task) = actor::spawn(cfg).await.expect("legacy wallet starts");

    // The pin was backfilled with the account's real UFVK.
    let st = WalletStore::read(&kp).unwrap();
    assert_eq!(
        st.pinned_ufvk(),
        Some(test_pinned_ufvk(net).as_str()),
        "startup backfills the pin trust-on-first-use"
    );

    // And the unlock-time seed check passes for the matching seed.
    handle
        .unlock(Passphrase::from("pw".to_string()), 60)
        .await
        .expect("the matching seed unlocks");
}

/// Layer 4b: a passphrase wallet whose database was swapped for a foreign account *before*
/// the pin existed (so the TOFU pin blessed the foreign account) is caught at the first
/// walletpassphrase: the decrypted seed does not derive the pinned account, the unlock is
/// refused with -4, and the wallet stays locked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn unlock_refuses_seed_that_does_not_derive_the_account() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();
    let kp = crate::wallet::store::keys_path(&wd);

    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_passphrase(
        &kp,
        Passphrase::from("pw".to_string()),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
        &test_pinned_ufvk(net),
    )
    .unwrap();
    WalletStore::strip_pin_for_tests(&kp); // legacy file: startup cannot verify, TOFU pins
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("planted", &foreign_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    // Startup succeeds: the wallet is locked, so only the (unverifiable) TOFU pin ran.
    let (cfg, _shutdown_tx) = offline_actor_cfg("tofu", wd);
    let (handle, _task) = actor::spawn(cfg).await.expect("locked wallet starts");

    // The correct passphrase decrypts the seed, but the seed does not derive the (foreign)
    // account, so the unlock is refused and the wallet stays locked.
    let e = handle
        .unlock(Passphrase::from("pw".to_string()), 60)
        .await
        .expect_err("a seed that does not derive the account must not unlock");
    assert_eq!(e.code, codes::RPC_WALLET_ERROR, "{e}");
    assert!(e.message.contains("does not derive"), "{e}");
    assert_eq!(
        handle.status().unlocked_until,
        Some(0),
        "the wallet must remain locked"
    );
}

/// Layer 4a: the identity/auto-unlock model has no walletpassphrase where a mismatch could
/// surface later, so the seed check runs at startup and a foreign database is fatal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn auto_unlock_refuses_foreign_database_at_startup() {
    use age::secrecy::ExposeSecret as _;

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();
    let kp = crate::wallet::store::keys_path(&wd);

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_mnemonic(
        &kp,
        std::iter::once(&recipient as &dyn age::Recipient),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
        &test_pinned_ufvk(net),
    )
    .unwrap();
    WalletStore::strip_pin_for_tests(&kp); // even without a pin, the seed check must catch it
    let id_path = wd.join("identity.txt");
    std::fs::write(&id_path, identity.to_string().expose_secret()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&id_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("planted", &foreign_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    let (mut cfg, _shutdown_tx) = offline_actor_cfg("auto", wd);
    cfg.age_identity = Some(id_path);
    let err = match actor::spawn(cfg).await {
        Ok(_) => panic!("auto-unlock against a foreign database must be fatal"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("does not derive"), "{err}");
}

/// A getrawtransaction that fails to reach the upstream must not leak the zebra
/// endpoint (host:port / cookie-file path) in the error returned to the client. The actor here
/// points at a dead 127.0.0.1:1 endpoint, so the fetch's connect fails; we assert the
/// client-facing message is the generic string and contains none of the upstream address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns an actor that loads the bundled prover (slow); offline otherwise"]
async fn getrawtransaction_error_does_not_leak_upstream_endpoint() {
    use zcash_protocol::TxId;

    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let wd = dir.path().to_path_buf();

    // A minimal identity-model wallet with a matching account, so the actor starts cleanly and
    // its binding check passes; sending/unlock are irrelevant to a raw-tx fetch.
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let mnemonic = <Mnemonic<English>>::from_phrase(TEST_PHRASE).unwrap();
    WalletStore::init_with_mnemonic(
        &crate::wallet::store::keys_path(&wd),
        std::iter::once(&recipient as &dyn age::Recipient),
        &mnemonic,
        BlockHeight::from_u32(1),
        net,
        &test_pinned_ufvk(net),
    )
    .unwrap();
    let mut db = open::init_dbs(net, &wd).unwrap();
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .unwrap();
    drop(db);

    // offline_actor_cfg dials a dead endpoint (127.0.0.1:1), so the on-demand fetch connect fails.
    let (cfg, _shutdown_tx) = offline_actor_cfg("leak", wd);
    let (handle, _task) = actor::spawn(cfg).await.unwrap();

    // A txid the wallet doesn't have forces the upstream-fetch path.
    let err = handle
        .get_raw_tx(TxId::from_bytes([7u8; 32]))
        .await
        .expect_err("fetch against a dead upstream must fail");
    let msg = err.message.to_lowercase();
    assert!(
        !msg.contains("127.0.0.1") && !msg.contains(":1") && !msg.contains("cookie"),
        "client error must not leak the upstream endpoint: {}",
        err.message
    );
    assert!(
        msg.contains("upstream node"),
        "expected the generic upstream message, got: {}",
        err.message
    );
}

/// [`read::LOAD_OUTPUTS_SQL`] must answer exactly what `v_tx_outputs` answers, and must reach
/// one transaction's outputs through indexes rather than a whole-wallet aggregation.
///
/// The statement is a hand-written restriction of that view to a single transaction, because
/// SQLite pushes no `WHERE` term through the view itself (measured below: filtering the view by
/// `transaction_id`, its own grouping column, still scans every note table). Hand-writing it
/// buys the index seeks and costs a copy of upstream's definition, so this test pins both
/// halves against the real schema: same rows as the view, and no full scans.
///
/// The wallet is populated by inserting directly into librustzcash's tables rather than by
/// scanning blocks. Nothing here needs the values to be cryptographically meaningful - the
/// view's shape (its joins, its `to_address` precedence, its grouping) is what is under test -
/// and minting real notes offline would need a chain. Two transactions are populated so that a
/// statement which ignored its `transaction_id` parameter would return the other one's rows.
#[test]
fn load_outputs_sql_matches_the_view_it_replaces() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).expect("init regtest dbs");
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    drop(db);

    let conn = rusqlite::Connection::open(open::data_db_path(engine_dir)).unwrap();
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    // `create_account` exposes the account's default address, so a row already exists to hang
    // received outputs off (the view reads `addresses.address`, its cached transparent receiver
    // and its key scope).
    let address_id: i64 = conn
        .query_row("SELECT id FROM addresses LIMIT 1", [], |r| r.get(0))
        .unwrap();

    populate_two_transactions(&conn, account_id, address_id);

    // The view's own answer, restricted to the transaction under test and read through exactly
    // the columns zecd reads.
    let via_view = "SELECT output_pool, output_index, from_account_uuid, to_account_uuid,
                           to_address, value, is_change, recipient_key_scope, memo
                    FROM v_tx_outputs
                    WHERE transaction_id = :id_tx
                      AND (:scope_account IS NULL OR to_account_uuid = :scope_account
                           OR from_account_uuid = :scope_account)
                    ORDER BY output_pool ASC, output_index ASC";

    // The account predicate is compared against `accounts.uuid` as stored, so bind the stored
    // bytes; both statements get the same binding, which is what makes the comparison meaningful.
    let account_uuid: Vec<u8> = conn
        .query_row("SELECT uuid FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    for (label, scope_param) in [
        ("unscoped", None),
        ("account-scoped", Some(account_uuid.clone())),
    ] {
        let mine = rows_of(&conn, read::LOAD_OUTPUTS_SQL, 1, scope_param.clone());
        let theirs = rows_of(&conn, via_view, 1, scope_param);
        assert_eq!(
            mine, theirs,
            "{label}: the hand-written statement must answer what v_tx_outputs answers"
        );
        assert!(
            !mine.is_empty(),
            "{label}: the fixture must produce rows, or this proves nothing"
        );
        // Pool order leads, then index within the pool - transparent (0), sapling (2), then
        // the two orchard (3) rows in index order.
        let keys: Vec<(i64, i64)> = mine.iter().map(|r| (r.0, r.1)).collect();
        assert_eq!(
            keys,
            vec![(0, 3), (2, 1), (3, 0), (3, 9)],
            "{label}: outputs must be ordered by (pool, index)"
        );
        // The paired Orchard row must report the address the wallet recorded when it created
        // the output, not the address it was received at.
        let paired = mine.iter().find(|r| (r.0, r.1) == (3, 0)).unwrap();
        assert_eq!(
            paired.2.as_deref(),
            Some("u1recorded"),
            "{label}: the recorded recipient wins over the receiving address"
        );
    }

    // Rows belong to the transaction that was asked for.
    let first = rows_of(&conn, read::LOAD_OUTPUTS_SQL, 1, None);
    let second = rows_of(&conn, read::LOAD_OUTPUTS_SQL, 2, None);
    assert_eq!(
        first, second,
        "the two fixture transactions are identical in shape, so their outputs must match"
    );

    // And the plan reaches them by index. A `SCAN` of any table holding a transaction's outputs
    // is the whole-history aggregation this statement exists to avoid.
    let plan = query_plan(
        &conn,
        read::LOAD_OUTPUTS_SQL,
        rusqlite::named_params! {":id_tx": 1i64, ":scope_account": None::<Vec<u8>>},
    );
    for table in [
        "sapling_received_notes",
        "orchard_received_notes",
        "ironwood_received_notes",
        "transparent_received_outputs",
        "sent_notes",
    ] {
        assert!(
            !plan.contains(&format!("SCAN {table}")),
            "single-transaction output lookup must not scan {table}; plan was:\n{plan}"
        );
    }

    // The premise, pinned: the view cannot be filtered cheaply, even on its own grouping
    // column. If a future SQLite learns to push this down, the hand-written statement stops
    // being necessary and this assertion is the thing that says so.
    let view_plan = query_plan(
        &conn,
        "SELECT output_pool FROM v_tx_outputs WHERE transaction_id = :id_tx",
        rusqlite::named_params! {":id_tx": 1i64},
    );
    assert!(
        view_plan.contains("SCAN orchard_received_notes"),
        "expected the view to still scan its base tables; plan was:\n{view_plan}"
    );
}

/// [`read::TX_RECORD_SQL`] must answer exactly what `v_transactions` answers for one
/// transaction, and must find it - or fail to find it - through the txid index.
///
/// Same reasoning as the outputs statement: `v_transactions` is an aggregate over the whole
/// wallet that no `WHERE` term reaches, so reading one transaction from it costs a full-history
/// aggregation whether or not the transaction is there. The miss is the case that hurt a real
/// deployment, where a reconciler probed hundreds of reorged-out txids in a row.
///
/// The columns compared are the ones [`read::TxRecord`] carries. `account_balance_delta` is the
/// interesting one: the view computes it by summing a union of received and spent note values,
/// and this statement has to reproduce that arithmetic from the base tables.
#[test]
fn transaction_record_matches_the_view_it_replaces() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).expect("init regtest dbs");
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    drop(db);

    let conn = rusqlite::Connection::open(open::data_db_path(engine_dir)).unwrap();
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let address_id: i64 = conn
        .query_row("SELECT id FROM addresses LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let account_uuid: Vec<u8> = conn
        .query_row("SELECT uuid FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    conn.execute("INSERT INTO blocks (height, hash, time, sapling_tree) VALUES (100, X'aa', 1700000000, X'00')", [])
        .unwrap();
    populate_two_transactions(&conn, account_id, address_id);
    // Spend one of the first transaction's notes in the second, so the balance delta has both
    // a positive and a negative term rather than only received value.
    let spent_note: i64 = conn
        .query_row(
            "SELECT id FROM orchard_received_notes WHERE transaction_id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
         VALUES (?1, 2)",
        rusqlite::params![spent_note],
    )
    .unwrap();

    let via_view = "SELECT v.mined_height, v.txid, v.expiry_height, v.account_balance_delta,
                           v.fee_paid, v.block_time, v.expired_unmined, v.tx_index,
                           b.hash AS block_hash,
                           CAST(strftime('%s', t.created) AS INTEGER) AS created_time
                    FROM v_transactions v
                    LEFT JOIN blocks b ON b.height = v.mined_height
                    LEFT JOIN transactions t ON t.txid = v.txid
                    WHERE v.txid = (SELECT txid FROM transactions WHERE id_tx = :id_tx)
                      AND (:scope_account IS NULL OR v.account_uuid = :scope_account)";

    for id_tx in [1i64, 2] {
        for (label, scope_param) in [
            ("unscoped", None),
            ("account-scoped", Some(account_uuid.clone())),
        ] {
            let mine = tx_row_of(&conn, read::TX_RECORD_SQL, id_tx, scope_param.clone());
            let theirs = tx_row_of(&conn, via_view, id_tx, scope_param);
            assert_eq!(
                mine, theirs,
                "{label}: transaction {id_tx} must read the same as v_transactions"
            );
            assert!(
                mine.is_some(),
                "{label}: transaction {id_tx} must be present, or this proves nothing"
            );
        }
    }
    // The spend must actually have moved the delta, or the arithmetic above is untested.
    let deltas: Vec<i64> = [1i64, 2]
        .iter()
        .map(|id| tx_row_of(&conn, read::TX_RECORD_SQL, *id, None).unwrap().3)
        .collect();
    assert_ne!(
        deltas[0], deltas[1],
        "the spend in transaction 2 must change its balance delta: {deltas:?}"
    );

    // A transaction the account was not part of reads as absent, exactly as the view emits no
    // row for it - this is what keeps a foreign unmined transaction out of wallet history.
    conn.execute(
        "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, expiry_height,
                                   min_observed_height)
         VALUES (99, X'cc', 100, 0, 0, 100)",
        [],
    )
    .unwrap();
    assert!(
        tx_row_of(&conn, read::TX_RECORD_SQL, 99, None).is_none(),
        "a stored transaction with none of the account's outputs must read as absent"
    );
    assert!(
        tx_row_of(&conn, via_view, 99, None).is_none(),
        "and the view agrees"
    );

    // A miss must be an index seek, not a scan: this is the reconciliation-sweep case.
    let plan = query_plan(
        &conn,
        "SELECT id_tx FROM transactions WHERE txid = :txid",
        rusqlite::named_params! {":txid": vec![0xffu8; 32]},
    );
    assert!(
        plan.contains("SEARCH transactions USING")
            && plan.contains("sqlite_autoindex_transactions_1"),
        "txid resolution must use the unique index; plan was:\n{plan}"
    );
    let plan = query_plan(
        &conn,
        read::TX_RECORD_SQL,
        rusqlite::named_params! {":id_tx": 1i64, ":scope_account": None::<Vec<u8>>},
    );
    for table in [
        "sapling_received_notes",
        "orchard_received_notes",
        "ironwood_received_notes",
        "transparent_received_outputs",
    ] {
        assert!(
            !plan.contains(&format!("SCAN {table}")),
            "single-transaction record must not scan {table}; plan was:\n{plan}"
        );
    }
}

/// The `TxRecord`-shaped columns of one transaction row, as a comparable tuple.
#[allow(clippy::type_complexity)]
fn tx_row_of(
    conn: &rusqlite::Connection,
    sql: &str,
    id_tx: i64,
    scope_account: Option<Vec<u8>>,
) -> Option<(
    Option<u32>,
    Vec<u8>,
    Option<u32>,
    i64,
    Option<i64>,
    Option<i64>,
    bool,
    Option<u32>,
    Option<Vec<u8>>,
    Option<i64>,
)> {
    let mut stmt = conn.prepare(sql).expect("prepare transaction statement");
    let mut rows = stmt
        .query(rusqlite::named_params! {":id_tx": id_tx, ":scope_account": scope_account})
        .expect("run transaction statement");
    let row = rows.next().expect("step transaction statement")?;
    // The base-table statement reports involvement rather than omitting the row, since it
    // selects the transaction before it knows whose it is; the view omits it. Normalize.
    if row
        .get::<_, Option<i64>>("involved")
        .ok()
        .flatten()
        .is_some_and(|n| n == 0)
    {
        return None;
    }
    Some((
        row.get("mined_height").unwrap(),
        row.get("txid").unwrap(),
        row.get("expiry_height").unwrap(),
        row.get("account_balance_delta").unwrap(),
        row.get("fee_paid").unwrap(),
        row.get("block_time").unwrap(),
        row.get("expired_unmined").unwrap(),
        row.get("tx_index").unwrap(),
        row.get("block_hash").unwrap(),
        row.get("created_time").unwrap(),
    ))
}

/// `getwalletinfo.txcount` must count what `v_transactions` counts, without aggregating the
/// whole wallet to do it. The view emits one row per `(account, transaction)` pair; the
/// replacement unions the same pairs out of the base tables, so the two must agree both
/// unscoped and scoped to the account.
#[test]
fn tx_count_matches_the_view_it_replaces() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).expect("init regtest dbs");
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    drop(db);

    let conn = rusqlite::Connection::open(open::data_db_path(engine_dir)).unwrap();
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let address_id: i64 = conn
        .query_row("SELECT id FROM addresses LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let account_uuid: Vec<u8> = conn
        .query_row("SELECT uuid FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    populate_two_transactions(&conn, account_id, address_id);
    // A spend as well as receives, so the union's spend arms contribute; and a transaction the
    // account has no part in, which neither side may count.
    let spent_note: i64 = conn
        .query_row(
            "SELECT id FROM orchard_received_notes WHERE transaction_id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute(
        "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
         VALUES (?1, 2)",
        rusqlite::params![spent_note],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, expiry_height,
                                   min_observed_height)
         VALUES (99, X'cc', 100, 0, 0, 100)",
        [],
    )
    .unwrap();

    for (label, scope_param) in [
        ("unscoped", None),
        ("account-scoped", Some(account_uuid.clone())),
    ] {
        let count = |sql: &str| -> i64 {
            conn.query_row(
                sql,
                rusqlite::named_params! {":scope_account": scope_param.clone()},
                |r| r.get(0),
            )
            .unwrap()
        };
        let mine = count(&format!(
            "SELECT COUNT(*) FROM ({}) WHERE (:scope_account IS NULL OR account_id = \
             (SELECT id FROM accounts WHERE uuid = :scope_account))",
            read::TX_INVOLVEMENT_SQL
        ));
        let theirs = count(
            "SELECT COUNT(*) FROM v_transactions \
             WHERE (:scope_account IS NULL OR account_uuid = :scope_account)",
        );
        assert_eq!(mine, theirs, "{label}: txcount must match v_transactions");
        assert_eq!(
            mine, 2,
            "{label}: the account is part of exactly the two populated transactions"
        );
    }
}

/// Populate two transactions' worth of outputs directly in librustzcash's tables.
///
/// Nothing here needs to be cryptographically meaningful: what the tests over this fixture
/// check is the *shape* of the history queries - their joins, their address precedence, their
/// grouping and their aggregate arithmetic - and minting real notes offline would need a chain.
/// Two transactions are populated so a statement that ignored its `transaction_id` parameter
/// would return the other one's rows.
fn populate_two_transactions(conn: &rusqlite::Connection, account_id: i64, address_id: i64) {
    for (id_tx, tag) in [(1i64, 0xa1u8), (2, 0xb2)] {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, expiry_height,
                                       min_observed_height)
             VALUES (?1, ?2, 100, 0, 0, 100)",
            rusqlite::params![id_tx, vec![tag; 32]],
        )
        .unwrap();
        // One output per pool, so the pool-then-index ordering is exercised and each arm of the
        // union contributes. Sapling and Orchard carry memos; transparent carries none by
        // construction (the view hard-codes NULL for it).
        conn.execute(
            "INSERT INTO sapling_received_notes
                 (transaction_id, output_index, account_id, diversifier, value, rcm, nf,
                  is_change, memo, address_id, recipient_key_scope)
             VALUES (?1, 1, ?2, X'00', 500, X'00', ?3, 0, X'61', ?4, 0)",
            rusqlite::params![id_tx, account_id, vec![tag; 32], address_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO orchard_received_notes
                 (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf,
                  is_change, memo, address_id, recipient_key_scope)
             VALUES (?1, 0, ?2, X'00', 700, X'00', X'00', ?3, 1, X'62', ?4, 1)",
            rusqlite::params![id_tx, account_id, vec![tag ^ 0xff; 32], address_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO transparent_received_outputs
                 (transaction_id, output_index, account_id, address, script, value_zat,
                  address_id)
             VALUES (?1, 3, ?2, 'tmtest', X'00', 900, ?3)",
            rusqlite::params![id_tx, account_id, address_id],
        )
        .unwrap();
        // A sent note that pairs with the Orchard output (same pool and index), so the view's
        // two arms merge into one row and its `to_address` precedence - the recorded recipient
        // wins over the receiving address - is exercised rather than assumed. A second sent
        // note has no received counterpart, the ordinary outgoing-payment shape.
        conn.execute(
            "INSERT INTO sent_notes
                 (transaction_id, output_pool, output_index, from_account_id, to_address, value,
                  memo)
             VALUES (?1, 3, 0, ?2, 'u1recorded', 700, X'62')",
            rusqlite::params![id_tx, account_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sent_notes
                 (transaction_id, output_pool, output_index, from_account_id, to_address, value,
                  memo)
             VALUES (?1, 3, 9, ?2, 'u1elsewhere', 1200, NULL)",
            rusqlite::params![id_tx, account_id],
        )
        .unwrap();
    }
}

/// The rows one output-loading statement returns, as comparable tuples.
type OutputRow = (
    i64,
    i64,
    Option<String>,
    i64,
    bool,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn rows_of(
    conn: &rusqlite::Connection,
    sql: &str,
    id_tx: i64,
    scope_account: Option<Vec<u8>>,
) -> Vec<OutputRow> {
    let mut stmt = conn.prepare(sql).expect("prepare output statement");
    let rows = stmt
        .query_map(
            rusqlite::named_params! {":id_tx": id_tx, ":scope_account": scope_account},
            |row| {
                Ok((
                    row.get("output_pool")?,
                    row.get("output_index")?,
                    row.get("to_address")?,
                    row.get("value")?,
                    row.get("is_change")?,
                    row.get("recipient_key_scope")?,
                    row.get("memo")?,
                    row.get("from_account_uuid")?,
                    row.get("to_account_uuid")?,
                ))
            },
        )
        .expect("run output statement");
    rows.map(|r| r.unwrap()).collect()
}

/// `EXPLAIN QUERY PLAN` for `sql`, as one newline-joined string. The parameters are bound
/// because SQLite requires every one of a prepared statement's parameters to be bound before
/// the statement steps, even under `EXPLAIN QUERY PLAN`; their values do not steer the plan
/// (an empty database has no `sqlite_stat1`, and what is under test is which index can serve a
/// predicate at all).
fn query_plan(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[(&str, &dyn rusqlite::ToSql)],
) -> String {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .expect("prepare EXPLAIN QUERY PLAN");
    let rows: Vec<String> = stmt
        .query_map(params, |row| row.get::<_, String>("detail"))
        .expect("run EXPLAIN QUERY PLAN")
        .map(|r| r.unwrap())
        .collect();
    rows.join("\n")
}

/// `[sync] fetch_memos = false` must drop **memos and nothing else** from the history reads.
///
/// That is the setting's whole contract, and the half a unit test can pin exhaustively: run the
/// same wallet through `query_transactions` and `get_transaction` both ways and require the two
/// records to be equal field for field once the memos are put back. A suppression that also
/// dropped an output, reordered them, or lost an address, a value or a key scope would pass a
/// test that only asserted "no memos"; this one fails.
///
/// Populated by inserting into librustzcash's tables directly, like the differential tests
/// above - the shape of the read is what is under test, not note cryptography. The fixture's
/// Sapling and Orchard outputs carry memos and its transparent output does not, so the test
/// covers both the dropped and the already-absent cases.
#[test]
fn omitting_memos_changes_nothing_but_the_memos() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).expect("init regtest dbs");
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    drop(db);

    let conn = rusqlite::Connection::open(open::data_db_path(engine_dir)).unwrap();
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let address_id: i64 = conn
        .query_row("SELECT id FROM addresses LIMIT 1", [], |r| r.get(0))
        .unwrap();
    populate_two_transactions(&conn, account_id, address_id);
    drop(conn);

    let query = |omit_memos: bool| {
        read::query_transactions(
            engine_dir,
            read::AccountScope::Any,
            &read::TxQuery {
                omit_memos,
                ..read::TxQuery::default()
            },
        )
        .expect("query_transactions")
    };
    let with = query(false);
    let without = query(true);

    assert!(
        with.iter()
            .any(|t| t.outputs.iter().any(|o| o.memo.is_some())),
        "the fixture must carry memos, or this test proves nothing"
    );
    assert!(
        without
            .iter()
            .all(|t| t.outputs.iter().all(|o| o.memo.is_none())),
        "omit_memos must leave no memo on any output: {without:?}"
    );
    assert_eq!(
        with.len(),
        without.len(),
        "omit_memos must not change which transactions are returned"
    );
    for (a, b) in with.iter().zip(without.iter()) {
        // Compare whole records with the memos put back, so any *other* field this suppression
        // disturbed shows up here rather than going unnoticed.
        let mut restored = b.clone();
        assert_eq!(
            restored.outputs.len(),
            a.outputs.len(),
            "omit_memos must not change how many outputs a transaction has"
        );
        for (out, original) in restored.outputs.iter_mut().zip(a.outputs.iter()) {
            out.memo.clone_from(&original.memo);
        }
        assert_eq!(
            format!("{restored:?}"),
            format!("{a:?}"),
            "omit_memos must change only the memo fields"
        );
    }

    // The single-transaction read is a separate statement (see `TX_RECORD_SQL`), so it gets the
    // same treatment rather than being assumed to follow.
    let txid = &with[0].txid_hex;
    let one = |omit_memos: bool| {
        read::get_transaction(net, engine_dir, read::AccountScope::Any, txid, omit_memos)
            .expect("get_transaction")
            .expect("the fixture transaction resolves")
    };
    let one_with = one(false);
    let mut one_without = one(true);
    assert!(
        one_without.outputs.iter().all(|o| o.memo.is_none()),
        "gettransaction must report no memos under omit_memos: {one_without:?}"
    );
    for (out, original) in one_without.outputs.iter_mut().zip(one_with.outputs.iter()) {
        out.memo.clone_from(&original.memo);
    }
    assert_eq!(
        format!("{one_without:?}"),
        format!("{one_with:?}"),
        "omit_memos must change only the memo fields on the single-transaction read"
    );
}

/// `read::wallet_spending_txids` must find a spend recorded in **every** pool's spend table.
///
/// This is the set `actor::request_in_scope` keeps enhancing under `[sync] fetch_memos = false`,
/// so a pool missing from its `UNION` would silently stop that pool's sends from being fetched -
/// and the symptom (a restored wallet's Sapling sends absent from `listtransactions`, its
/// Orchard ones present) is one no offline test would otherwise catch. Ironwood is in the list
/// deliberately: post-NU6.3 it is the pool the wallet's own sends actually spend from.
///
/// A transaction the wallet only received in must NOT be in the set - that is the other half of
/// the predicate, and the reason the setting saves anything at all.
#[test]
fn wallet_spending_txids_covers_every_pool() {
    let net = network::regtest();
    let dir = tempfile::tempdir().unwrap();
    let engine_dir = dir.path();
    let mut db = open::init_dbs(net, engine_dir).expect("init regtest dbs");
    db.create_account("primary", &test_seed(), &genesis_birthday(), None)
        .expect("create regtest account");
    drop(db);

    let conn = rusqlite::Connection::open(open::data_db_path(engine_dir)).unwrap();
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let address_id: i64 = conn
        .query_row("SELECT id FROM addresses LIMIT 1", [], |r| r.get(0))
        .unwrap();

    // Transactions 1 and 2 hold the wallet's received outputs (one per pool); transactions
    // 3..=6 each spend one of them, one pool apiece. Transaction 7 is the control: the wallet
    // received in it and spent nothing, so the whole point is that it stays out of the set.
    populate_two_transactions(&conn, account_id, address_id);
    for (id_tx, tag) in [(3i64, 0xc3u8), (4, 0xc4), (5, 0xc5), (6, 0xc6), (7, 0xc7)] {
        conn.execute(
            "INSERT INTO transactions (id_tx, txid, mined_height, tx_index, expiry_height,
                                       min_observed_height)
             VALUES (?1, ?2, 101, 1, 0, 101)",
            rusqlite::params![id_tx, vec![tag; 32]],
        )
        .unwrap();
    }
    // An ironwood note to spend: `populate_two_transactions` does not create one (the views it
    // pins predate the pool), so add it here rather than widening that shared fixture.
    conn.execute(
        "INSERT INTO ironwood_received_notes
             (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf,
              is_change, memo, address_id, recipient_key_scope, note_version)
         VALUES (1, 1, ?1, X'00', 1100, X'00', X'00', X'dd', 0, X'63', ?2, 0, 3)",
        rusqlite::params![account_id, address_id],
    )
    .unwrap();

    let note_id = |table: &str| -> i64 {
        conn.query_row(&format!("SELECT id FROM {table} LIMIT 1"), [], |r| r.get(0))
            .unwrap_or_else(|e| panic!("a row in {table}: {e}"))
    };
    for (table, column, source, spender) in [
        (
            "sapling_received_note_spends",
            "sapling_received_note_id",
            "sapling_received_notes",
            3i64,
        ),
        (
            "orchard_received_note_spends",
            "orchard_received_note_id",
            "orchard_received_notes",
            4,
        ),
        (
            "ironwood_received_note_spends",
            "ironwood_received_note_id",
            "ironwood_received_notes",
            5,
        ),
        (
            "transparent_received_output_spends",
            "transparent_received_output_id",
            "transparent_received_outputs",
            6,
        ),
    ] {
        conn.execute(
            &format!("INSERT INTO {table} ({column}, transaction_id) VALUES (?1, ?2)"),
            rusqlite::params![note_id(source), spender],
        )
        .unwrap();
    }
    drop(conn);

    let spending = read::wallet_spending_txids(engine_dir).expect("wallet_spending_txids");
    for (tag, pool) in [
        (0xc3u8, "sapling"),
        (0xc4, "orchard"),
        (0xc5, "ironwood"),
        (0xc6, "transparent"),
    ] {
        assert!(
            spending.contains(&zcash_protocol::TxId::from_bytes([tag; 32])),
            "a {pool} spend must put its transaction in the set: {spending:?}"
        );
    }
    assert!(
        !spending.contains(&zcash_protocol::TxId::from_bytes([0xc7u8; 32])),
        "a transaction the wallet did not spend in must stay out of the set - that exclusion \
         is what fetch_memos = false actually skips: {spending:?}"
    );
    assert_eq!(spending.len(), 4, "no other transaction qualifies");
}
