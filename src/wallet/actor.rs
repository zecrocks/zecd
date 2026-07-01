//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, create_proposed_transactions, decrypt_and_store_transaction,
    extract_and_store_transaction_from_pczt, input_selection::GreedyInputSelector,
    propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{
    Account, AccountBirthday, AccountPurpose, AccountSource, TransactionDataRequest,
    TransactionStatus, WalletRead, WalletWrite,
};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::proto::service;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::{AccountUuid, FsBlockDb};
use zcash_primitives::transaction::Transaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedProtocol, TxId};
use zip32::DiversifierIndex;
use zip321::TransactionRequest;

use crate::backend::Server;
use crate::backoff::Backoff;
use crate::chain::{AnySource, BroadcastOutcome, ChainSource, MempoolStream};
use crate::config::SendPrivacy;
use crate::error::{codes, RpcError};
use crate::network::ZNetwork;
use crate::pools::{Pool, PoolSet};
use crate::sync::engine;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::read;
use crate::wallet::{
    make_handle, store, ConnState, FirstSeen, RawTx, SharedSeed, SyncStatus, WalletCommand,
    WalletHandle,
};

/// Note-management defaults for change splitting (match zcash-devtool's send defaults).
const TARGET_NOTE_COUNT: usize = 4;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000; // 0.1 ZEC

/// The Orchard proving + verifying keys, built once and shared (read-only) across every wallet
/// actor via `Arc`. These are wallet-independent (they're the Orchard circuit's keys), and
/// `ProvingKey::build()` is a full `keygen_vk`+`keygen_pk` - seconds of work - so the fused
/// librustzcash send path (which rebuilds the proving key on *every* transaction) pays that
/// cost per send. Building it here once and feeding it to the PCZT prove path eliminates that
/// per-send overhead (the `[spend] cache_proving_key` knob, default on). The verifying key is
/// kept too so the PCZT extract step doesn't regenerate it each send.
pub struct ProvingKeyCache {
    orchard_pk: orchard::circuit::ProvingKey,
    orchard_vk: orchard::circuit::VerifyingKey,
}

impl ProvingKeyCache {
    /// Build the Orchard proving + verifying keys. Expensive (full key generation); call once
    /// at startup, off the async runtime (e.g. under `spawn_blocking`).
    pub fn build() -> Self {
        ProvingKeyCache {
            orchard_pk: orchard::circuit::ProvingKey::build(),
            orchard_vk: orchard::circuit::VerifyingKey::build(),
        }
    }
}

/// Cap on sends queued behind an in-flight proof (`[spend] pipeline_proving`). Each queued send
/// is a blocked RPC handler, so the work-queue semaphore already bounds this; the cap is a
/// defensive backstop so a misconfigured client can't grow the queue without limit. Past it,
/// `begin_or_queue_send` sheds with `-4` back-pressure (the caller retries), like the async-op
/// registry's inflight cap.
const MAX_QUEUED_SENDS: usize = 64;

/// A send deferred because another send's proof is still in flight. Sends stay serialized even
/// when proving is pipelined off the actor: only one PCZT is ever uncommitted at a time, so there
/// is no double-spend surface and no reservation overlay is needed. A send arriving mid-proof waits here and
/// starts once the in-flight one commits.
struct PendingSend {
    request: TransactionRequest,
    confirmations: Option<ConfirmationsPolicy>,
    privacy: SendPrivacy,
    reply: oneshot::Sender<Result<TxId, RpcError>>,
}

/// A send whose prove+sign finished on a blocking thread, routed back to the actor so phase C
/// (extract + store + mark-spent + broadcast) runs on the single writer.
struct SendCompletion {
    /// The signed PCZT ready to extract+store, or the error that aborted phase A/B (proposal,
    /// PCZT build, proving, signing, or a caught panic in the proof job).
    result: Result<pczt::Pczt, RpcError>,
    /// The confirmations policy this send used, to enrich a `-6` if storing surfaces one.
    policy: ConfirmationsPolicy,
    /// The send's shape (input/action counts), carried through for the latency log line.
    shape: SendShape,
    /// Wall time phase A (select + PCZT build) took on the actor.
    build_elapsed: Duration,
    /// Wall time the off-actor prove+sign took (phase B).
    prove_elapsed: Duration,
    /// The caller awaiting the txid.
    reply: oneshot::Sender<Result<TxId, RpcError>>,
}

/// Deadlines for RPCs issued on an already-connected channel. The dial timeout covers only
/// the TCP/TLS connect, so a peer that hangs *after* accepting would otherwise stall the
/// actor's command loop indefinitely (HTTP/2 keepalive on the channel is the systemic
/// backstop; these make the critical paths deterministic and snappier).
///
/// The post-connect health check may include the one-time subtree-root stream (hundreds of
/// roots on mainnet), so it gets a generous budget...
const PREPARE_TIMEOUT: Duration = Duration::from_secs(60);
/// Unary calls (broadcast, tip refresh, tx fetch) on the live channel.
const UNARY_RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// Minimum spacing between retries after a sync error, so a persistent failure (e.g. an
/// unrecoverable reorg) can't spin the actor loop at full speed reconnecting and re-failing.
const SYNC_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// How many transaction-enhancement requests to service per `enhance_step` call before
/// yielding back to the actor loop. Enhancement runs only once the block scan is caught up,
/// but it can be a multi-hour backlog on a from-birthday restore (one upstream
/// `getrawtransaction` then decrypt/store per request). Draining it in bounded batches - instead
/// of one monolithic pass - keeps the single-writer actor responsive: queued commands (sends) are
/// serviced between batches and the shrinking backlog is republished on `SyncStatus` after each
/// one. At ~0.3s/request this is a few seconds of work per batch.
const ENHANCE_BATCH: usize = 16;

/// Whether a [`TransactionDataRequest`] is one zecd can actually service (and therefore one that
/// counts toward the enhancement backlog). `TransactionsInvolvingAddress` needs a transparent-txid
/// query the `ChainSource` trait has no source for, so it's skipped - and deliberately *not*
/// counted, since it never drains and would otherwise pin the backlog above zero forever.
fn is_serviceable_request(req: &TransactionDataRequest) -> bool {
    matches!(
        req,
        TransactionDataRequest::GetStatus(_) | TransactionDataRequest::Enhancement(_)
    )
}

/// At bootstrap, warn when the derived scan floor lands more than one note-commitment-tree
/// shard (2^16 blocks) below the wallet birthday - the symptom of the scan queue flooring at
/// an in-progress subtree boundary instead of the birthday (the failure `maybe_bootstrap_account`
/// guards against by setting the chain tip only after the account, with its birthday, exists).
const BOOTSTRAP_SCAN_FLOOR_WARN_GAP: u32 = 1 << 16;

// NB: the unmined-tx rebroadcast interval is configurable (`[sync] rebroadcast_secs`,
// default 60) and arrives via `ActorConfig::rebroadcast_interval`. It covers sends whose
// original broadcast failed (their notes are already locked in the DB until expiry) and
// mempool drops across upstream restarts; bitcoind keeps retransmitting unconfirmed wallet
// txs the same way. A node that already has the tx rejects the duplicate, which is harmless.

thread_local! {
    /// Set while we deliberately `catch_unwind` librustzcash's progress estimator, so the
    /// panic hook can stay quiet for that (expected, handled) panic only.
    static SILENCE_PROGRESS_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Install a panic hook that suppresses the (caught) librustzcash progress-estimator panic
/// while leaving all other panics fully reported. Call once at startup.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if SILENCE_PROGRESS_PANIC.with(|f| f.get()) {
            return;
        }
        default(info);
    }));
}

/// Parameters needed to launch a wallet actor.
pub struct ActorConfig {
    pub name: String,
    pub network: ZNetwork,
    pub wallet_dir: PathBuf,
    /// Path to this wallet's `keys.toml` (may live outside `wallet_dir`, e.g. a mounted Secret).
    pub keys_path: PathBuf,
    /// The upstream zebrad endpoint.
    pub server: Server,
    pub sync_interval: Duration,
    /// Minimum spacing between unmined-tx rebroadcast passes.
    pub rebroadcast_interval: Duration,
    /// Per-attempt dial timeout.
    pub connect_timeout: Duration,
    /// Reconnect backoff base/max delays.
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    pub age_identity: Option<PathBuf>,
    pub auto_unlock: bool,
    /// Rebuild the account from `keys.toml` when the data directory is empty (`[keys]
    /// bootstrap_from_keys`).
    pub bootstrap: bool,
    /// The wallet-wide confirmations policy (`[spend]` config; ZIP-315 3/10 by default),
    /// anchoring balances, spend proposals, and the `-6` enrichment.
    pub confirmations_policy: ConfirmationsPolicy,
    /// Cap on Orchard actions per send (`[spend] orchard_action_limit`; 0 disables it).
    pub orchard_action_limit: usize,
    /// Shared cached Orchard proving/verifying keys (`[spend] cache_proving_key`). `Some`
    /// selects the PCZT prove path with the cached key; `None` selects the legacy fused path
    /// (`create_proposed_transactions`), which rebuilds the proving key per send. Built once in
    /// `daemon::run` and cloned into every actor (the key is wallet-independent). NB: the PCZT
    /// path here signs only Orchard spends, so a wallet that can spend Sapling notes
    /// (`enabled_pools` includes Sapling) falls back to the fused path regardless - see `do_send`.
    pub orchard_keys: Option<Arc<ProvingKeyCache>>,
    /// Run the proving step off the actor so a long send doesn't freeze sync (`[spend]
    /// pipeline_proving`). Only engages on the cached-Orchard PCZT path; off by default.
    pub pipeline_proving: bool,
    /// Shielded pools this wallet receives into and spends from (change pool selection).
    pub enabled_pools: PoolSet,
    /// Receivers included by default in this wallet's Unified Addresses.
    pub default_receivers: PoolSet,
    /// Flips to `true` on Ctrl-C/`stop`; the actor exits its loop (between sync batches)
    /// so the `WalletDb` is dropped cleanly before the process ends.
    pub shutdown: watch::Receiver<bool>,
}

struct WalletActor {
    name: String,
    network: ZNetwork,
    wallet_dir: PathBuf,
    /// Path to this wallet's `keys.toml` (may live outside `wallet_dir`).
    keys_path: PathBuf,
    /// The upstream zebrad endpoint.
    server: Server,
    connect_timeout: Duration,
    backoff: Backoff,
    /// When the next reconnect attempt is allowed (a backoff deadline, not a fixed tick), so
    /// commands interrupting the idle wait don't advance the backoff.
    reconnect_at: Instant,
    sync_interval: Duration,
    rebroadcast_interval: Duration,
    confirmations_policy: ConfirmationsPolicy,
    /// Cap on Orchard actions per send (`[spend] orchard_action_limit`; 0 disables it).
    orchard_action_limit: usize,
    /// Shielded pools this wallet receives into and spends from.
    enabled_pools: PoolSet,
    /// Receivers included by default in this wallet's Unified Addresses.
    default_receivers: PoolSet,
    /// Transient first-seen times for unmined txs, shared with the read-path handle. Stamped when
    /// the mempool stream first stores an unmined tx; pruned once the tx mines. Never persisted
    /// (zecd is stateless). See [`crate::wallet::FirstSeen`].
    first_seen: FirstSeen,
    /// The wallet's account, or `None` while a bootstrap is pending (empty data directory whose
    /// account hasn't been rebuilt from `keys.toml` yet - e.g. an encrypted wallet awaiting its
    /// first `walletpassphrase`).
    account_id: Option<AccountUuid>,
    account_index: Option<zip32::AccountId>,
    /// When `Some`, the account must be (re)created from `keys.toml` at this birthday height once
    /// the seed is available and an upstream is connected. `None` once an account exists.
    pending_bootstrap: Option<BlockHeight>,
    db_data: WriteDb,
    db_cache: FsBlockDb,
    client: Option<AnySource>,
    /// Whether the current connection has emitted its "connected ... chain tip N" log line.
    /// Set once per connection (on the first successful tip refresh, when the tip is known)
    /// and reset on disconnect, so connect/disconnect are logged as matched transitions
    /// rather than once per tip refresh or per dropped client.
    connected_logged: bool,
    /// Live mempool subscription, open only while caught up to the tip. Both backends
    /// stream current + newly-arriving mempool txs and close the stream when a new block
    /// is mined (lightwalletd does this natively; the zebra backend synthesizes it from a
    /// `getrawmempool` poller); each tx is trial-decrypted and stored unmined if it pays
    /// this wallet, which is what lets `getunconfirmedbalance`/`listtransactions` reflect
    /// an incoming payment before its first confirmation (bitcoind parity). Best-effort:
    /// any stream error just drops it and the next caught-up pass reopens.
    mempool: Option<MempoolStream>,
    /// Shared (`Arc`) so the proving step can be moved onto a blocking thread when
    /// `pipeline_proving` is on (`LocalTxProver` is built once and is read-only during proving).
    prover: Arc<LocalTxProver>,
    /// Cached Orchard keys for the PCZT send path (`None` = legacy fused path). See
    /// [`ProvingKeyCache`].
    orchard_keys: Option<Arc<ProvingKeyCache>>,
    /// `[spend] pipeline_proving`: run a send's prove+sign off the actor so it doesn't freeze
    /// sync. Only engages on the cached-Orchard PCZT path (see [`Self::pipeline_eligible`]).
    pipeline_proving: bool,
    /// Whether a pipelined send's proof is currently running on a blocking thread. While `true`,
    /// new sends queue (in [`Self::send_queue`]) rather than starting - sends stay serialized.
    send_in_flight: bool,
    /// Sends deferred behind the in-flight proof, started in FIFO order as each one commits.
    send_queue: VecDeque<PendingSend>,
    /// Loopback channel: the off-actor proof job posts its [`SendCompletion`] here, and the
    /// actor's command loop drains it to run phase C on the single writer.
    send_done_tx: mpsc::Sender<SendCompletion>,
    send_done_rx: mpsc::Receiver<SendCompletion>,
    /// The decrypted seed, shared with the [`WalletHandle`] so `walletlock` can zeroize it
    /// without waiting on this actor's command queue. See [`SharedSeed`].
    seed: SharedSeed,
    status_tx: watch::Sender<SyncStatus>,
    cmd_rx: mpsc::Receiver<WalletCommand>,
    tip_height: Option<u32>,
    tip_hash: Option<String>,
    /// Last time the unmined-tx rebroadcast pass ran (`None` = not yet).
    last_rebroadcast: Option<Instant>,
    /// Whether the note-commitment subtree roots have been downloaded at least once this
    /// process. After the first fetch they persist in the wallet DB, so later (re)connects do a
    /// cheap liveness probe instead of re-streaming every root.
    subtree_roots_synced: bool,
    /// The wallet's birthday height (read from `keys.toml` at spawn). Published on
    /// `SyncStatus` for the health server's "connected" readiness sanity check.
    birthday: u32,
    /// Whether the wallet is passphrase-encrypted (read from `keys.toml` at spawn). Gates the
    /// Bitcoin-Core-style `walletpassphrase`/`walletlock` behavior.
    encrypted: bool,
    /// Whether the wallet is watch-only (its account is an imported UFVK with no spending
    /// material). Spend commands refuse with Bitcoin Core's -4.
    watch_only: bool,
    /// For an encrypted wallet that's currently unlocked: when the seed auto-relocks. Re-running
    /// `walletpassphrase` overwrites it (resetting the timer); `walletlock` clears it.
    unlock_until: Option<Instant>,
    /// Serviceable transaction-data requests already attempted in the current enhancement drain.
    /// Mirrors zcash-devtool/zkv's per-pass `satisfied` set, but carried across `enhance_step`
    /// batches so a request the upstream can't satisfy (left in the DB after servicing) is
    /// re-fetched at most once per drain instead of spinning the batch loop. Cleared whenever a
    /// sync batch does work (new blocks may add or re-satisfy requests). Entries removed from the
    /// DB by librustzcash on success simply never reappear.
    enhance_satisfied: std::collections::BTreeSet<TransactionDataRequest>,
    /// Graceful-shutdown signal (see [`ActorConfig::shutdown`]).
    shutdown: watch::Receiver<bool>,
}

/// Open the wallet, derive its account info, optionally unlock the seed, build the prover,
/// and spawn the actor task. Returns a clonable handle plus the task's join handle (awaited
/// at shutdown so the wallet DB closes cleanly before the runtime is torn down).
pub async fn spawn(
    cfg: ActorConfig,
) -> anyhow::Result<(WalletHandle, tokio::task::JoinHandle<()>)> {
    if !store::WalletStore::exists(&cfg.keys_path) {
        return Err(anyhow!(
            "wallet '{}' is not initialized ({} missing); run `zecd init --wallet {}`",
            cfg.name,
            cfg.keys_path.display(),
            cfg.name
        ));
    }

    // The data directory must be writable: zecd creates/updates data.sqlite and blocks/
    // there. Probe it up front so a read-only mount fails with a clear error now,
    // not later at an awkward moment - e.g. when a `walletpassphrase` arrives and the bootstrap
    // tries to create the account.
    ensure_dir_writable(&cfg.wallet_dir)
        .with_context(|| format!("wallet '{}' data directory is not usable", cfg.name))?;

    let db_data = open::init_dbs(cfg.network, &cfg.wallet_dir)?;
    let db_cache = open::open_fsblockdb(&cfg.wallet_dir)?;
    let st = store::WalletStore::read(&cfg.keys_path)?;
    let encrypted = st.is_encrypted();

    // Resolve the account. A normal data directory already has one. An *empty* data directory
    // (keys.toml present, but data.sqlite carries no account) is the bootstrap case: when
    // enabled, rebuild the account from keys.toml once the seed is available - immediately for an
    // identity/auto-unlock wallet, at the first `walletpassphrase` for an encrypted one.
    let (account_id, account_index, watch_only, pending_bootstrap) =
        match try_select_account(&db_data)? {
            Some((id, index, wo)) => (Some(id), index, wo, None),
            None => {
                if !st.has_seed() {
                    // Watch-only wallet (no seed, and the UFVK isn't cached in keys.toml):
                    // nothing on disk can rebuild a viewable account.
                    return Err(anyhow!(
                        "wallet '{}' has an empty data directory and no spending seed in \
                         keys.toml (watch-only): it cannot be rebuilt. Recreate it with \
                         `zecd init --ufvk`.",
                        cfg.name
                    ));
                }
                if !cfg.bootstrap {
                    return Err(anyhow!(
                        "wallet '{}' has no account in {}; run `zecd init`, or enable \
                         [keys] bootstrap_from_keys to rebuild the data directory from keys.toml.",
                        cfg.name,
                        open::data_db_path(&cfg.wallet_dir).display()
                    ));
                }
                info!(
                    "[{}] empty data directory with keys.toml present: rebuilding the account \
                     from keys.toml (birthday {}) once the seed is available{}",
                    cfg.name,
                    u32::from(st.birthday),
                    if encrypted {
                        " (call walletpassphrase to unlock)"
                    } else {
                        ""
                    }
                );
                // A seed wallet is never watch-only; the rebuilt account is a spending account.
                (None, None, false, Some(st.birthday))
            }
        };

    // Determine the wallet's encryption mode, and for unencrypted wallets optionally decrypt
    // the seed up-front for unattended sending. An encrypted wallet has no passphrase at rest,
    // so it cannot auto-unlock - it starts locked and requires `walletpassphrase` (matching
    // Bitcoin Core's encrypted-wallet behavior). A watch-only wallet has no seed anywhere, so
    // the whole unlock machinery is moot for it.
    let birthday = u32::from(st.birthday);
    let mut seed = SeedKeeper::locked();
    if watch_only {
        info!(
            "[{}] watch-only wallet (imported UFVK): balances, history, and addresses are \
             available; spending and wallet-encryption RPCs are disabled",
            cfg.name
        );
    } else if encrypted {
        info!(
            "[{}] wallet is passphrase-encrypted; it starts locked - call walletpassphrase to unlock for sending",
            cfg.name
        );
    } else if cfg.auto_unlock {
        if let Some(identity) = &cfg.age_identity {
            if st.has_seed() {
                match keys::decrypt_seed_with_identity(&st, identity) {
                    Ok(Some(s)) => {
                        seed.set(s);
                        info!("[{}] seed unlocked for unattended sending", cfg.name);
                    }
                    Ok(None) => {}
                    Err(e) => warn!("[{}] could not decrypt seed at startup: {e}", cfg.name),
                }
            }
        } else {
            warn!(
                "[{}] auto_unlock is set but no age identity configured; sending will require walletpassphrase",
                cfg.name
            );
        }
    } else {
        // An identity-encrypted wallet with auto_unlock=false is a dead end for sending:
        // it starts locked, and walletpassphrase on a non-passphrase wallet is -15 (like
        // bitcoind's unencrypted wallets) - there is no RPC that can unlock it. Reads still
        // work, so don't refuse to start; warn loudly instead.
        warn!(
            "[{}] auto_unlock=false on an identity-encrypted wallet: sends will fail (-13) and \
             walletpassphrase cannot unlock it (-15). Enable auto_unlock, or re-create the wallet \
             passphrase-encrypted with `zecd init --encrypt` (then walletpassphrase unlocks).",
            cfg.name
        );
    }

    // The local prover bundles Sapling parameters; build it once (off the async threads). Shared
    // via `Arc` so the proving step can be handed to a blocking thread under `pipeline_proving`.
    let prover = Arc::new(
        tokio::task::spawn_blocking(LocalTxProver::bundled)
            .await
            .map_err(|e| anyhow!("failed to build prover: {e}"))?,
    );

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    // Loopback for pipelined-send completions. Bounded by `MAX_QUEUED_SENDS` since at most that
    // many sends can be outstanding (one in flight + the queue), and only one is ever proving.
    let (send_done_tx, send_done_rx) = mpsc::channel(MAX_QUEUED_SENDS + 1);
    // Seed the status channel with the wallet's static facts (encryption mode, watch-only)
    // so an RPC racing the actor's first `update_status` - which only runs after the initial
    // connect attempt - never reports a default-shaped wallet (e.g. `private_keys_enabled:
    // true` for a watch-only wallet, or a missing `unlocked_until` for an encrypted one).
    let (status_tx, status_rx) = watch::channel(SyncStatus {
        encrypted,
        watch_only,
        birthday: Some(birthday),
        unlocked_until: encrypted.then_some(0),
        ..SyncStatus::default()
    });

    // Shared, transient first-seen map: the actor stamps unmined txs into it and the read-path
    // handle reads it. Never persisted (zecd is stateless).
    let first_seen: FirstSeen =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // Share the seed with the handle so `walletlock` can zeroize it directly (the fast path),
    // but only for a passphrase-encrypted wallet - the only kind that can be locked. An
    // unencrypted (identity/auto-unlock) or watch-only wallet keeps `None` on the handle, so its
    // `walletlock` falls through to the actor's `-15`, and its always-resident seed is never
    // zeroized out from under an in-flight send.
    let seed: SharedSeed = std::sync::Arc::new(std::sync::Mutex::new(seed));
    let handle_seed = encrypted.then(|| seed.clone());

    let actor = WalletActor {
        name: cfg.name.clone(),
        network: cfg.network,
        wallet_dir: cfg.wallet_dir.clone(),
        keys_path: cfg.keys_path.clone(),
        server: cfg.server,
        connect_timeout: cfg.connect_timeout,
        backoff: Backoff::new(cfg.reconnect_base, cfg.reconnect_max),
        reconnect_at: Instant::now(),
        sync_interval: cfg.sync_interval,
        rebroadcast_interval: cfg.rebroadcast_interval,
        confirmations_policy: cfg.confirmations_policy,
        orchard_action_limit: cfg.orchard_action_limit,
        enabled_pools: cfg.enabled_pools.clone(),
        default_receivers: cfg.default_receivers.clone(),
        first_seen: first_seen.clone(),
        account_id,
        account_index,
        pending_bootstrap,
        db_data,
        db_cache,
        client: None,
        connected_logged: false,
        prover,
        orchard_keys: cfg.orchard_keys,
        pipeline_proving: cfg.pipeline_proving,
        send_in_flight: false,
        send_queue: VecDeque::new(),
        send_done_tx,
        send_done_rx,
        seed,
        status_tx,
        cmd_rx,
        tip_height: None,
        tip_hash: None,
        mempool: None,
        last_rebroadcast: None,
        subtree_roots_synced: false,
        birthday,
        encrypted,
        watch_only,
        unlock_until: None,
        enhance_satisfied: std::collections::BTreeSet::new(),
        shutdown: cfg.shutdown,
    };

    let task = tokio::spawn(actor.run());

    Ok((
        make_handle(
            cfg.name,
            cfg.wallet_dir,
            cfg.network,
            cfg.confirmations_policy,
            cfg.enabled_pools,
            cfg.default_receivers,
            first_seen,
            handle_seed,
            cmd_tx,
            status_rx,
        ),
        task,
    ))
}

/// Fetch the upstream's current tip and record it as the wallet DB's chain tip, returning the
/// parsed tip height plus its block hash (upstream/internal byte order). This is the first step
/// of the pre-spend catch-up (`sync_to_tip_for_send`): librustzcash derives a transaction's
/// target height - and thus its expiry (target + expiry delta) - from the DB's chain tip, so
/// before a spend the tip must reflect the *real* chain, not zecd's last-scanned height (which
/// lags under load). Recording the tip also extends the scan queue up to it, which the catch-up
/// loop then scans. Extracted from `refresh_tip` as a free function so that "a stale DB tip
/// advances to the upstream tip" contract can be unit-tested against the fake zebrad without
/// spinning up a full actor + prover.
pub(crate) async fn fetch_and_store_chain_tip(
    client: &mut impl ChainSource,
    db: &mut WriteDb,
) -> anyhow::Result<(BlockHeight, Vec<u8>)> {
    let (tip, hash) = fetch_chain_tip(client).await?;
    db.update_chain_tip(tip)?;
    Ok((tip, hash))
}

/// Fetch the upstream's current tip (parsed height + block hash in upstream/internal byte
/// order) without touching the wallet DB. `refresh_tip` uses this before the account bootstrap
/// has run: with no account, `update_chain_tip` would floor the scan queue at a subtree
/// boundary far below the birthday (see the comment in `refresh_tip`), so the tip must not be
/// recorded yet.
async fn fetch_chain_tip(client: &mut impl ChainSource) -> anyhow::Result<(BlockHeight, Vec<u8>)> {
    let chain_tip = tokio::time::timeout(UNARY_RPC_TIMEOUT, client.latest_block())
        .await
        .map_err(|_| anyhow!("latest_block timed out after {UNARY_RPC_TIMEOUT:?}"))??;
    let tip = BlockHeight::try_from(chain_tip.height)
        .map_err(|_| anyhow!("chain tip height out of range"))?;
    Ok((tip, chain_tip.hash))
}

/// The actor's view of the wallet's (single) account: its id, the ZIP-32 index spending keys
/// derive at (`None` when no spending is possible), and whether the account is watch-only
/// (imported UFVK - `init --ufvk`). `Ok(None)` means the data directory carries no account yet
/// (a bootstrap candidate), as distinct from a genuine read error.
fn try_select_account(
    db: &WriteDb,
) -> anyhow::Result<Option<(AccountUuid, Option<zip32::AccountId>, bool)>> {
    let ids = db.get_account_ids()?;
    let Some(id) = ids.first().copied() else {
        return Ok(None);
    };
    let account = db
        .get_account(id)?
        .ok_or_else(|| anyhow!("selected account not found"))?;
    let index = account.source().key_derivation().map(|d| d.account_index());
    let watch_only = matches!(
        account.source(),
        AccountSource::Imported {
            purpose: AccountPurpose::ViewOnly,
            ..
        }
    );
    Ok(Some((id, index, watch_only)))
}

/// Probe that `dir` exists and is writable (create it if missing), so a read-only data
/// directory is caught at launch with a clear message rather than at the first write.
fn ensure_dir_writable(dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating data directory {}", dir.display()))?;
    let probe = dir.join(".zecd-write-test");
    std::fs::write(&probe, b"zecd").with_context(|| {
        format!(
            "data directory {} is not writable (zecd must create and update data.sqlite \
             and blocks/ there)",
            dir.display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Error returned by address/spend operations while the account is still being rebuilt from
/// `keys.toml` on an empty data directory (no account exists yet).
fn account_not_ready() -> RpcError {
    RpcError::wallet(
        "wallet account is not ready: it is being rebuilt from keys.toml on an empty data \
         directory (an encrypted wallet must be unlocked with walletpassphrase first)",
    )
}

/// Bitcoin Core's exact refusal for spend/key operations on a wallet without private keys
/// (`-4`, wallet.cpp); zecd's watch-only (UFVK) wallets surface it for the same calls.
fn private_keys_disabled() -> RpcError {
    RpcError::wallet("Error: Private keys are disabled for this wallet")
}

/// Map a `get_address_for_index` failure onto an `RpcError`. The reuse case (an exact
/// diversifier index previously exposed with a *different* receiver set) gets zcashd's exact
/// `z_getaddressforaccount` wording; everything else is a generic wallet error.
fn map_address_for_index_error(e: SqliteClientError) -> RpcError {
    match e {
        SqliteClientError::DiversifierIndexReuse(j, _) => RpcError::wallet(format!(
            "Error: address at diversifier index {} was already generated with different \
             receiver types.",
            u128::from(j)
        )),
        other => RpcError::wallet(format!("address generation failed: {other}")),
    }
}

/// Render a tree-state frontier (the hex-encoded `final_state` from a `tree_state` reply) for
/// the bootstrap log: its size in bytes when present, or `absent` when the upstream served no
/// frontier for that pool. Hex is two characters per byte.
fn describe_frontier(hex_final_state: &str) -> String {
    if hex_final_state.is_empty() {
        "absent".to_string()
    } else {
        format!("present({}B)", hex_final_state.len() / 2)
    }
}

impl WalletActor {
    async fn run(mut self) {
        if let Err(e) = self.connect().await {
            warn!("[{}] initial upstream connect failed: {e}", self.name);
        }
        if self.client.is_some() {
            if let Err(e) = self.refresh_tip().await {
                warn!("[{}] initial tip refresh failed: {e}", self.name);
                self.client = None;
            }
        }
        self.update_status();

        let mut more_work = true;
        loop {
            // Exit between sync batches once shutdown is signalled, so Ctrl-C/`stop` doesn't
            // wait out a long catch-up scan and the DB connection is dropped cleanly.
            if *self.shutdown.borrow() {
                info!("[{}] wallet actor shutting down", self.name);
                return;
            }
            // Relock an encrypted wallet whose passphrase timeout has elapsed. Checked every
            // iteration (between sync batches) so the seed doesn't linger long past expiry; the
            // `select!` branch below handles the idle case, and `do_send` has a hard backstop.
            self.relock_if_expired();
            if more_work {
                // Commit any pipelined send whose proof just finished, before the next sync
                // batch - phase C is short (store + bounded broadcast) and the caller is waiting.
                // `finish_send_caught` pumps the send queue, so a deferred send starts promptly.
                while let Ok(done) = self.send_done_rx.try_recv() {
                    self.finish_send_caught(done).await;
                }
                // Service any queued commands first so writers aren't starved by sync.
                loop {
                    match self.cmd_rx.try_recv() {
                        Ok(cmd) => {
                            if self.handle_command_caught(cmd).await {
                                return;
                            }
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => return,
                    }
                }
                match self.sync_step_caught().await {
                    Ok(worked) => {
                        if worked {
                            more_work = true;
                            // New blocks were scanned, which may add or re-satisfy enhancement
                            // requests - start the next drain from a clean slate.
                            self.enhance_satisfied.clear();
                        } else {
                            // Caught up: give any unmined wallet txs another shot at the mempool,
                            // pull the full data (memos, …) for transactions seen only as compact
                            // blocks, and (re)subscribe to incoming mempool txs for 0-conf visibility.
                            self.maybe_rebroadcast().await;
                            // Drain one bounded batch of the enhancement backlog. Keep `more_work`
                            // set while requests remain so the loop keeps draining (servicing queued
                            // commands and republishing the shrinking backlog between batches)
                            // instead of going idle for a full `sync_interval` between each.
                            // Panic-isolated (#83): enhancement fetches and decrypts full txs, so it
                            // shares the block scan's exposure to hostile/edge data - a poison tx is
                            // logged and treated as "no more work this pass" rather than taking the
                            // actor (and all wallet writes) down.
                            let more_enhance = self.enhance_step_caught().await;
                            self.ensure_mempool_stream().await;
                            more_work = more_enhance;
                        }
                    }
                    Err(e) => {
                        self.mark_disconnected(format!("sync error: {e}"));
                        // Pace retries after a sync error. A *persistent* sync error (e.g. an
                        // unrecoverable reorg whose rewind target has no checkpoint) would
                        // otherwise spin: dropping the client makes the idle loop reconnect
                        // immediately, the reconnect succeeds (the upstream is healthy, so the
                        // connect backoff never engages and is reset on success), and the very
                        // next batch re-hits the same error - hundreds of times a second, pegging
                        // a core and flooding the log. A fixed floor caps that to one attempt per
                        // interval; a transient error just costs this small delay.
                        self.reconnect_at = Instant::now() + SYNC_ERROR_RETRY_INTERVAL;
                        self.update_status();
                        more_work = false;
                    }
                }
            } else {
                // Idle: poll at `sync_interval` while connected; when disconnected, wait until the
                // backoff deadline (`reconnect_at`) instead of hammering a dead upstream on a fixed
                // tick. Using a deadline (not `next_delay()` per loop) means commands interrupting
                // the wait don't inflate the backoff - it advances only on an actual failed connect.
                let wait = if self.client.is_some() {
                    self.sync_interval
                } else {
                    self.reconnect_at.saturating_duration_since(Instant::now())
                };
                // The mempool stream is moved out for the duration of the `select!` so its
                // arm's borrow can't conflict with the `&mut self` the handlers need; the
                // handlers run after the event is chosen (and the stream put back).
                enum IdleEvent {
                    Shutdown(Result<(), watch::error::RecvError>),
                    Cmd(Option<WalletCommand>),
                    // Boxed: a `SendCompletion` carries a proven PCZT (hundreds of bytes), which
                    // would otherwise bloat every `IdleEvent` (clippy::large_enum_variant).
                    SendDone(Option<Box<SendCompletion>>),
                    Relock,
                    Tick,
                    Mempool(anyhow::Result<Option<service::RawTransaction>>),
                }
                let event = {
                    let mut mempool = self.mempool.take();
                    let event = tokio::select! {
                        res = self.shutdown.changed() => IdleEvent::Shutdown(res),
                        maybe_cmd = self.cmd_rx.recv() => IdleEvent::Cmd(maybe_cmd),
                        done = self.send_done_rx.recv() => IdleEvent::SendDone(done.map(Box::new)),
                        _ = relock_sleep(self.unlock_until) => IdleEvent::Relock,
                        _ = tokio::time::sleep(wait) => IdleEvent::Tick,
                        res = mempool_next(&mut mempool) => IdleEvent::Mempool(res),
                    };
                    self.mempool = mempool;
                    event
                };
                match event {
                    // Wakes the idle wait promptly on Ctrl-C/`stop`; the loop-top check exits.
                    // An Err (sender dropped) only happens at teardown - stop right here, since
                    // `changed()` would otherwise resolve Err on every iteration (a busy loop).
                    IdleEvent::Shutdown(res) => {
                        if res.is_err() {
                            info!("[{}] wallet actor shutting down", self.name);
                            return;
                        }
                    }
                    IdleEvent::Cmd(Some(cmd)) => {
                        if self.handle_command_caught(cmd).await {
                            return;
                        }
                    }
                    IdleEvent::Cmd(None) => return,
                    // A pipelined send's proof finished while idle: commit it (phase C). The
                    // sender is a field, so `recv()` only yields `None` at teardown.
                    IdleEvent::SendDone(Some(done)) => self.finish_send_caught(*done).await,
                    IdleEvent::SendDone(None) => return,
                    IdleEvent::Relock => self.relock_if_expired(),
                    IdleEvent::Tick => {
                        if self.client.is_none() {
                            if let Err(e) = self.connect().await {
                                // Schedule the next attempt with exponential backoff + jitter.
                                let delay = self.backoff.next_delay();
                                self.reconnect_at = Instant::now() + delay;
                                warn!(
                                    "[{}] reconnect failed: {e}; retrying in {delay:?}",
                                    self.name
                                );
                                self.update_status();
                            }
                        }
                        if self.client.is_some() {
                            match self.refresh_tip().await {
                                Ok(()) => more_work = true,
                                Err(e) => {
                                    self.mark_disconnected(format!("tip refresh failed: {e}"));
                                    self.update_status();
                                }
                            }
                        }
                    }
                    IdleEvent::Mempool(Ok(Some(raw))) => {
                        // Mempool txs come from a not-necessarily-honest upstream and are
                        // trial-decrypted here; isolate any panic so it can't take the actor
                        // (and thus all wallet writes) down. See `handle_command_caught`.
                        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            self.store_mempool_tx(raw)
                        }))
                        .is_err()
                        {
                            error!(
                                "[{}] mempool tx handler panicked; the actor continues",
                                self.name
                            );
                        }
                    }
                    IdleEvent::Mempool(Ok(None)) => {
                        // lightwalletd closes the stream when a new block is mined: sync it
                        // now instead of waiting out the rest of the poll interval. The next
                        // caught-up pass reopens the stream.
                        self.mempool = None;
                        match self.refresh_tip().await {
                            Ok(()) => more_work = true,
                            Err(e) => {
                                self.mark_disconnected(format!("tip refresh failed: {e}"));
                                self.update_status();
                            }
                        }
                    }
                    IdleEvent::Mempool(Err(e)) => {
                        // Best-effort subscription: drop it and let the regular liveness
                        // checks decide whether the connection itself is unhealthy.
                        tracing::debug!("[{}] mempool stream error: {e}", self.name);
                        self.mempool = None;
                    }
                }
            }
        }
    }

    /// Run one writer command, catching any panic so a single bad command can't silently take
    /// the whole actor - and thus every wallet *write* - down until process restart (reads
    /// bypass the actor and would keep working, masking the outage). The one *expected* panic
    /// (the librustzcash progress-estimator underflow) is handled at its own call site; this is
    /// the backstop for anything unforeseen on the send/shield/store path, e.g. a librustzcash
    /// edge or odd data from a not-fully-trusted upstream. On a caught panic the command's reply
    /// sender is dropped (the caller sees an error), but the actor loop survives.
    async fn handle_command_caught(&mut self, cmd: WalletCommand) -> bool {
        use futures_util::FutureExt as _;
        match std::panic::AssertUnwindSafe(self.handle_command(cmd))
            .catch_unwind()
            .await
        {
            Ok(stop) => stop,
            Err(_) => {
                error!(
                    "[{}] wallet command handler panicked; the actor continues and the command \
                     failed (this is a bug - please report it)",
                    self.name
                );
                false
            }
        }
    }

    /// Run one sync batch, catching any panic so it can't take the actor (and thus every wallet
    /// *write*) down until process restart. The block scan funnels upstream block bytes through
    /// the same `decrypt_and_store_transaction` as the command and mempool paths, so hostile or
    /// edge chain data could trip a librustzcash panic here too; this is the third untrusted-data
    /// ingress and gets the same isolation as `handle_command_caught` and the mempool-path guard.
    /// A caught panic is surfaced to the caller as an error, so the loop paces retries via the
    /// persistent-sync-error path instead of spinning on a poison batch (and `/readyz` reflects it).
    async fn sync_step_caught(&mut self) -> anyhow::Result<bool> {
        use futures_util::FutureExt as _;
        match std::panic::AssertUnwindSafe(self.sync_step())
            .catch_unwind()
            .await
        {
            Ok(res) => res,
            Err(_) => {
                error!(
                    "[{}] wallet sync batch panicked; the actor continues (this is a bug - \
                     please report it)",
                    self.name
                );
                Err(anyhow!("sync batch panicked"))
            }
        }
    }

    /// Run [`enhance_step`](Self::enhance_step), catching any panic. Enhancement
    /// fetches full transactions from the upstream and decrypts them through the same
    /// `decrypt_and_store_transaction`, so it shares the block scan's exposure to hostile/edge
    /// data; isolate it for the same reason. Best-effort already, so a caught panic is just
    /// logged and treated as "no more work this pass" - the still-pending requests are retried
    /// on the next caught-up pass. Returns whether serviceable requests still remain (see
    /// [`enhance_step`](Self::enhance_step)); a caught panic returns `false`.
    async fn enhance_step_caught(&mut self) -> bool {
        use futures_util::FutureExt as _;
        match std::panic::AssertUnwindSafe(self.enhance_step())
            .catch_unwind()
            .await
        {
            Ok(more) => more,
            Err(_) => {
                error!(
                    "[{}] transaction enhancement panicked; the actor continues",
                    self.name
                );
                false
            }
        }
    }

    /// Drop the upstream client and, if the connection had been announced (its "connected"
    /// line was logged), warn that it was lost with the reason. Gating on `connected_logged`
    /// keeps disconnects matched to connects: a client dropped before it ever came up (a
    /// failed dial / health check) is reported by the connect path instead, not here.
    fn mark_disconnected(&mut self, reason: impl std::fmt::Display) {
        self.client = None;
        if std::mem::take(&mut self.connected_logged) {
            warn!(
                "[{}] disconnected from {}: {reason}",
                self.name,
                self.server.describe()
            );
        }
    }

    /// Connect to the upstream zebrad endpoint. On success, store the client (after the
    /// subtree-root health check) and reset the reconnect backoff. On failure, leave
    /// `self.client` as `None` and return the error.
    async fn connect(&mut self) -> anyhow::Result<()> {
        // Any open mempool stream belongs to the channel being replaced; drop it so it can't
        // pin the old connection alive. It is reopened on the next caught-up sync pass.
        self.mempool = None;
        let describe = self.server.describe();
        info!("[{}] connecting to {}", self.name, describe);
        let client = self.server.connect_timeout(self.connect_timeout).await?;
        self.client = Some(client);
        let client = self.client.as_mut().expect("just set");
        // A reachable-but-unhealthy upstream can still fail here; treat that as a failed connect.
        if let Err(e) = prepare_client(
            client,
            &mut self.db_data,
            self.network,
            &mut self.subtree_roots_synced,
            PREPARE_TIMEOUT,
        )
        .await
        {
            warn!("[{}] health check failed on {}: {e}", self.name, describe);
            self.client = None;
            return Err(e);
        }
        self.backoff.reset();
        // NB: do not call `update_status()` here - `get_wallet_summary`'s progress
        // estimator underflows if invoked before the chain tip is set (see `refresh_tip`).
        Ok(())
    }

    /// Subscribe to the upstream's mempool stream if not already subscribed. Called only when
    /// caught up to the chain tip (mempool txs are meaningless to a wallet that's still
    /// scanning history). Failures are logged at debug and retried on the next caught-up
    /// pass - older or unusual upstreams may not serve a mempool view, and 0-conf
    /// visibility is a best-effort improvement, not a correctness requirement.
    async fn ensure_mempool_stream(&mut self) {
        if self.mempool.is_some() || self.tip_height.is_none() {
            return;
        }
        let Some(client) = self.client.as_mut() else {
            return;
        };
        // Bounded like other unary calls: only the subscription setup is awaited here; the
        // stream body is consumed incrementally from the idle loop.
        match tokio::time::timeout(UNARY_RPC_TIMEOUT, client.subscribe_mempool()).await {
            Ok(Ok(stream)) => {
                tracing::debug!("[{}] subscribed to the mempool stream", self.name);
                self.mempool = Some(stream);
            }
            Ok(Err(e)) => {
                tracing::debug!("[{}] mempool stream unavailable: {e}", self.name);
            }
            Err(_) => {
                tracing::debug!(
                    "[{}] mempool stream subscription timed out after {UNARY_RPC_TIMEOUT:?}",
                    self.name
                );
            }
        }
    }

    /// Count the serviceable transaction-data requests still pending in this enhancement drain -
    /// the "enhancement backlog" surfaced on `SyncStatus.pending_enhancements`. This is the work
    /// that remains *after* the block scan reaches the tip: compact blocks carry no memos, so each
    /// pending request is one full-transaction fetch + decrypt/store away from being served.
    /// Requests already attempted this drain (`enhance_satisfied`) and unsupported ones
    /// ([`is_serviceable_request`]) are excluded, so a clean drain converges to zero. A DB read
    /// error reports zero (best-effort; the count is observability, not a correctness gate).
    fn count_pending_enhancements(&self) -> u64 {
        match self.db_data.transaction_data_requests() {
            Ok(reqs) => reqs
                .iter()
                .filter(|r| is_serviceable_request(r) && !self.enhance_satisfied.contains(r))
                .count() as u64,
            Err(e) => {
                tracing::debug!("[{}] counting pending enhancements: {e}", self.name);
                0
            }
        }
    }

    /// Service one bounded batch of the wallet's pending transaction-data requests - the
    /// "enhancement" step. `scan_cached_blocks` records these
    /// (`WalletRead::transaction_data_requests`) while scanning compact blocks, which carry no
    /// memos and no full transparent data: for each request, fetch the full transaction from the
    /// upstream and either decrypt+store it (which fills in `v_tx_outputs.memo` on received
    /// shielded outputs) or record its chain status. Called only when caught up to the tip.
    ///
    /// Without this, a memo on a transaction the wallet only ever saw as a compact block -
    /// every receive picked up during initial sync or a `--restore`, and any live receive the
    /// mempool stream missed - never appears in `gettransaction`/`listtransactions`, because
    /// the compact-block scan records the tx as mined with a NULL memo and nothing ever
    /// backfills it. (A receive the mempool stream *does* catch is already enhanced: that path
    /// stores the full tx via `decrypt_and_store_transaction`.)
    ///
    /// Returns `true` if serviceable requests still remain (so the caller should keep driving the
    /// drain), `false` when the backlog is empty, the client dropped, or shutdown was signalled.
    /// On a from-birthday restore the backlog can be tens of thousands of requests (hours of work
    /// at one upstream fetch each), so this services at most [`ENHANCE_BATCH`] per call and yields:
    /// the actor loop services queued commands and republishes the shrinking
    /// `pending_enhancements` count between batches, instead of disappearing into one monolithic
    /// pass that hides the backlog and starves writers for hours.
    ///
    /// Mirrors zcash-devtool's `enhance` command and zkv's `enhance`. Best-effort: a transport
    /// failure drops the client (so the next loop reconnects/fails over) and ends the batch; the
    /// still-pending requests are retried on the next caught-up pass. librustzcash removes each
    /// request once it is satisfied, so a clean drain converges and stops re-fetching.
    async fn enhance_step(&mut self) -> bool {
        let Some(tip) = self.tip_height else {
            return false;
        };
        if self.client.is_none() {
            return false;
        }
        let chain_tip = BlockHeight::from_u32(tip);
        let requests = match self.db_data.transaction_data_requests() {
            Ok(r) => r,
            Err(e) => {
                warn!("[{}] reading transaction data requests: {e}", self.name);
                return false;
            }
        };
        // Serviceable requests not yet attempted in this drain. Inserting each into
        // `enhance_satisfied` (whether it was removed from the DB on success or left in place
        // because the upstream couldn't satisfy it) guarantees forward progress: the unattempted
        // set strictly shrinks every call, so the drain terminates instead of re-fetching the same
        // front-of-queue requests forever.
        let pending: Vec<TransactionDataRequest> = requests
            .into_iter()
            .filter(|r| is_serviceable_request(r) && !self.enhance_satisfied.contains(r))
            .collect();
        let mut handled = 0usize;
        for req in &pending {
            // Bail promptly on Ctrl-C/`stop` rather than fetching out the rest of a long backlog.
            if *self.shutdown.borrow() {
                return false;
            }
            if let Err(e) = self.service_data_request(req, chain_tip).await {
                // A transport failure has already dropped the client (a DB-write error just ends
                // the batch); either way stop here and retry the remainder on the next pass rather
                // than spinning on a persistent failure.
                tracing::debug!("[{}] transaction enhancement aborted: {e}", self.name);
                self.update_status();
                return false;
            }
            self.enhance_satisfied.insert(req.clone());
            handled += 1;
            if handled >= ENHANCE_BATCH {
                break;
            }
        }
        // Republish the shrinking backlog (now reflected by `enhance_satisfied`) so /status,
        // getwalletinfo and readiness track the drain between batches.
        self.update_status();
        // More to do only if the batch cap stopped us short of the serviceable requests in hand.
        pending.len() > handled
    }

    /// Handle one [`TransactionDataRequest`] for [`enhance_step`]. Returns `Err` only
    /// for failures worth aborting the whole pass (transport, or a wallet-write error).
    async fn service_data_request(
        &mut self,
        req: &TransactionDataRequest,
        chain_tip: BlockHeight,
    ) -> anyhow::Result<()> {
        match req {
            TransactionDataRequest::GetStatus(txid) => {
                let status = self.fetch_full_tx(*txid, chain_tip).await?.map_or(
                    TransactionStatus::TxidNotRecognized,
                    |(_, mined)| {
                        mined.map_or(TransactionStatus::NotInMainChain, TransactionStatus::Mined)
                    },
                );
                self.db_data.set_transaction_status(*txid, status)?;
            }
            TransactionDataRequest::Enhancement(txid) => {
                match self.fetch_full_tx(*txid, chain_tip).await? {
                    None => self
                        .db_data
                        .set_transaction_status(*txid, TransactionStatus::TxidNotRecognized)?,
                    Some((tx, mined)) => {
                        decrypt_and_store_transaction(
                            &self.network,
                            &mut self.db_data,
                            &tx,
                            mined,
                        )?;
                    }
                }
            }
            // `TransactionsInvolvingAddress` scans a transparent address's on-chain history.
            // zecd hands out Orchard-only receivers and the `ChainSource` trait exposes no
            // transparent-txid query, so there's nothing to fetch here; skip it (best-effort).
            // Marking it satisfied for the pass keeps the re-query loop from spinning.
            other => {
                tracing::debug!(
                    "[{}] skipping unsupported transaction data request: {other:?}",
                    self.name
                );
            }
        }
        Ok(())
    }

    /// Fetch a full transaction from the upstream and parse it for enhancement, returning the
    /// decoded [`Transaction`] and its mined height (`None` for an unmined tx), or `None` when
    /// the upstream doesn't know the txid. Transport failures surface as `Err` (the client has
    /// already been dropped by [`Self::fetch_tx_from_upstream`]).
    async fn fetch_full_tx(
        &mut self,
        txid: TxId,
        chain_tip: BlockHeight,
    ) -> anyhow::Result<Option<(Transaction, Option<BlockHeight>)>> {
        let Some(raw) = self
            .fetch_tx_from_upstream(txid)
            .await
            .map_err(|e| anyhow!("{e}"))?
        else {
            return Ok(None);
        };
        let mined_height = raw.mined_height.map(BlockHeight::from_u32);
        // An unmined tx is assumed created under the current tip's consensus branch (matches
        // zcash-devtool/zkv's enhance and `store_mempool_tx`).
        let tx = Transaction::read(
            &raw.data[..],
            BranchId::for_height(&self.network, mined_height.unwrap_or(chain_tip)),
        )?;
        Ok(Some((tx, mined_height)))
    }

    /// Trial-decrypt one mempool transaction against the wallet's keys and store it (as an
    /// unmined row) if any output is ours. `decrypt_and_store_transaction` no-ops for
    /// unrelated txs, so no pre-filtering is needed. Best-effort: a tx that fails to parse
    /// or store is logged and skipped.
    fn store_mempool_tx(&mut self, raw: service::RawTransaction) {
        let Some(tip) = self.tip_height else { return };
        // lightwalletd reports height 0 for mempool txs; a positive height means it was
        // already mined by the time it was streamed.
        let mined_height = (raw.height > 0 && raw.height <= u64::from(u32::MAX))
            .then(|| BlockHeight::from_u32(raw.height as u32));
        // A mempool tx targets the next block.
        let branch_height = mined_height.unwrap_or_else(|| BlockHeight::from_u32(tip) + 1);
        let tx = match Transaction::read(
            &raw.data[..],
            BranchId::for_height(&self.network, branch_height),
        ) {
            Ok(tx) => tx,
            Err(e) => {
                tracing::debug!("[{}] skipping unparseable mempool tx: {e}", self.name);
                return;
            }
        };
        let txid = tx.txid();
        match decrypt_and_store_transaction(&self.network, &mut self.db_data, &tx, mined_height) {
            Ok(()) => {
                tracing::debug!("[{}] processed mempool tx {txid}", self.name);
                // If the tx is ours and still unmined, stamp when we first saw it so
                // `gettransaction`/`listtransactions` can report `time`/`timereceived` (Bitcoin
                // Core's `nTimeReceived`) while it has no block time. This is held in memory only
                // - zecd is stateless, so it is never persisted (a restart/restore rebuilds it as
                // the mempool stream re-observes the tx, or it mines and the block time wins).
                let txid_hex = txid.to_string();
                if mined_height.is_none() && super::read::tx_exists(&self.wallet_dir, &txid_hex) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if let Ok(mut map) = self.first_seen.lock() {
                        map.entry(txid_hex).or_insert(now);
                    }
                }
            }
            Err(e) => warn!("[{}] failed to store mempool tx {txid}: {e}", self.name),
        }
    }

    /// Drop first-seen entries whose tx has since mined (or otherwise left the unmined set), so
    /// the transient map stays bounded by the currently-unmined wallet txs. Best-effort and
    /// cheap; runs on the caught-up rebroadcast cadence.
    fn prune_first_seen(&self) {
        let Ok(mut map) = self.first_seen.lock() else {
            return;
        };
        if map.is_empty() {
            return;
        }
        match super::read::unmined_txids(&self.wallet_dir) {
            Ok(unmined) => {
                let unmined: std::collections::HashSet<String> = unmined.into_iter().collect();
                map.retain(|txid, _| unmined.contains(txid));
            }
            Err(e) => tracing::debug!("[{}] pruning first-seen map: {e}", self.name),
        }
    }

    async fn refresh_tip(&mut self) -> anyhow::Result<()> {
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| anyhow!("not connected"))?;
        let prev = self.tip_height;
        // Only push the chain tip into the wallet DB once an account exists. `update_chain_tip`
        // derives the scan queue, and with no account `wallet_birthday` (MIN over accounts) is
        // NULL - in which case librustzcash floors the tip-priority scan range at the lowest
        // note-commitment *subtree* boundary (the min over the Sapling and Orchard shard tips)
        // instead of the account birthday (zcash_client_sqlite `scanning::update_chain_tip`'s
        // `tip_shard_entry`). For a from-`keys.toml` rebuild on testnet that dragged the rescan
        // ~350k blocks below the birthday (to the in-progress *Sapling* shard's start) for an
        // Orchard-only wallet, a ~16-minute restore. The bootstrap creates the account only
        // *after* the actor's first connect/refresh, so calling `update_chain_tip` here with no
        // account would insert that low range, and a later call can't raise an existing range's
        // floor. So defer it: `maybe_bootstrap_account` calls `update_chain_tip` itself right
        // after creating the account (birthday now set → the scan floors at the birthday). We
        // still record the tip height/hash below so the bootstrap can run.
        let (tip, hash) = if self.account_id.is_some() {
            fetch_and_store_chain_tip(client, &mut self.db_data).await?
        } else {
            fetch_chain_tip(client).await?
        };
        self.tip_height = Some(u32::from(tip));
        // Announce a freshly established connection now that we know the upstream's tip. Logged
        // once per connection (reset by `mark_disconnected`), so connect/disconnect pair up.
        if !self.connected_logged {
            self.connected_logged = true;
            info!(
                "[{}] connected to {}; chain tip {}",
                self.name,
                self.server.describe(),
                u32::from(tip)
            );
        }
        tracing::debug!(
            "[{}] tip refreshed: {:?} -> {} (suggest_scan_ranges drives the rescan/rewind)",
            self.name,
            prev,
            u32::from(tip)
        );
        if hash.len() == 32 {
            let mut h = hash;
            h.reverse();
            self.tip_hash = Some(hex::encode(h));
        }
        self.update_status();
        Ok(())
    }

    async fn sync_step(&mut self) -> anyhow::Result<bool> {
        if self.client.is_none() {
            self.connect().await?;
        }
        // Rebuild the account from keys.toml if the data directory was empty. Until that
        // succeeds there is nothing to scan, so don't run a batch.
        self.maybe_bootstrap_account().await;
        if self.account_id.is_none() {
            return Ok(false);
        }
        let worked = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| anyhow!("not connected"))?;
            engine::sync_one_batch(
                &self.name,
                client,
                &self.network,
                &self.wallet_dir,
                &mut self.db_cache,
                &mut self.db_data,
            )
            .await?
        };
        self.update_status();
        Ok(worked)
    }

    /// Rebuild the wallet account from `keys.toml` on an empty data directory (the bootstrap
    /// path). Best-effort and idempotent: requires the seed to be loaded (so an encrypted wallet
    /// waits for its first `walletpassphrase`), a live upstream, and a known tip; when any is
    /// missing it returns and is retried on the next pass. The birthday's tree state is fetched
    /// fresh from the upstream (never cached on disk), reusing the exact path `zecd init` takes.
    async fn maybe_bootstrap_account(&mut self) {
        let Some(birthday_height) = self.pending_bootstrap else {
            return;
        };
        if self.account_id.is_some() {
            self.pending_bootstrap = None;
            return;
        }
        // A copy of the seed (zeroized on drop); absent means the wallet is still locked.
        let Some(seed) = seed_guard(&self.seed).clone_seed() else {
            return;
        };
        let Some(tip) = self.tip_height else {
            return;
        };
        if self.client.is_none() {
            return;
        }
        // Fetch the tree state just before the birthday (mirrors `init`). Height 0 has no tree
        // state and is rejected upstream; clamp to >= 1.
        let prior = u32::from(birthday_height).saturating_sub(1).max(1);
        let treestate = {
            let client = self.client.as_mut().expect("checked above");
            match tokio::time::timeout(
                UNARY_RPC_TIMEOUT,
                client.tree_state(BlockHeight::from_u32(prior)),
            )
            .await
            {
                Ok(Ok(ts)) => ts,
                Ok(Err(e)) => {
                    warn!(
                        "[{}] bootstrap: fetching birthday tree state failed: {e}",
                        self.name
                    );
                    self.client = None;
                    return;
                }
                Err(_) => {
                    warn!(
                        "[{}] bootstrap: birthday tree-state fetch timed out",
                        self.name
                    );
                    self.client = None;
                    return;
                }
            }
        };
        // Summarize the birthday tree state for the bootstrap log *before* `from_treestate`
        // consumes it. Every field here is already in hand - no extra upstream calls. The
        // requested height (`prior`) must come back unchanged; a mismatch means the upstream
        // served a different height than asked (a zebra/indexer bug), so flag it loudly.
        let treestate_returned = u32::try_from(treestate.height).unwrap_or(u32::MAX);
        let sapling_frontier = describe_frontier(&treestate.sapling_tree);
        let orchard_frontier = describe_frontier(&treestate.orchard_tree);
        if prior != treestate_returned {
            warn!(
                "[{}] bootstrap: treestate height mismatch - requested {prior}, upstream \
                 returned {treestate_returned}",
                self.name
            );
        }
        let birthday =
            match AccountBirthday::from_treestate(treestate, Some(BlockHeight::from_u32(tip))) {
                Ok(b) => b,
                Err(_) => {
                    warn!(
                        "[{}] bootstrap: could not derive account birthday from tree state",
                        self.name
                    );
                    return;
                }
            };
        if let Err(e) = self
            .db_data
            .create_account("primary", &seed, &birthday, None)
        {
            warn!(
                "[{}] bootstrap: creating the account failed: {e}",
                self.name
            );
            return;
        }
        match try_select_account(&self.db_data) {
            Ok(Some((id, index, watch_only))) => {
                // Invariant: a zecd wallet is the first (and only) account of its seed, so
                // `create_account` on the freshly-wiped, account-less DB must derive at ZIP-32
                // account index 0 - the same index `zecd init` used, so the rebuilt account is
                // the *same* wallet. Anything else would silently rebuild a different account.
                debug_assert_eq!(
                    index,
                    zip32::AccountId::try_from(0u32).ok(),
                    "bootstrap must rebuild the account at ZIP-32 index 0"
                );
                self.account_id = Some(id);
                self.account_index = index;
                self.watch_only = watch_only;
                self.pending_bootstrap = None;
                // First `update_chain_tip` with the account (and its birthday) now present - see
                // `refresh_tip`. This is what derives the scan queue with a non-NULL
                // `wallet_birthday`, so the rescan floors at the birthday instead of an
                // in-progress subtree boundary far below it.
                if let Err(e) = self.db_data.update_chain_tip(BlockHeight::from_u32(tip)) {
                    warn!(
                        "[{}] bootstrap: update_chain_tip after account creation failed: {e}",
                        self.name
                    );
                }
                // The scan floor: the lowest height the queue will scan, derived from the now
                // birthday-anchored scan ranges (a local sqlite read zecd runs every sync - no
                // upstream call). Its gap below the birthday is the actionable signal for the
                // "scanning far below birthday" pathology this bootstrap path exists to avoid.
                let scan_floor = match self.db_data.suggest_scan_ranges() {
                    Ok(ranges) => ranges
                        .iter()
                        .map(|r| u32::from(r.block_range().start))
                        .min(),
                    Err(e) => {
                        tracing::debug!(
                            "[{}] bootstrap: suggest_scan_ranges for log failed: {e}",
                            self.name
                        );
                        None
                    }
                };
                let birthday = u32::from(birthday_height);
                let blocks_below_birthday = scan_floor.map(|f| birthday.saturating_sub(f));
                // One structured INFO summarizing the bootstrap, all from data already in hand:
                // requested-vs-returned treestate height, per-pool frontier presence/size (a
                // Sapling frontier on an Orchard-only wallet is the tell for a wasted Sapling
                // scan), the active pool set, and the scan floor vs birthday.
                info!(
                    wallet = %self.name,
                    keys_birthday = birthday,
                    treestate_requested = prior,
                    treestate_returned,
                    sapling_frontier = %sapling_frontier,
                    orchard_frontier = %orchard_frontier,
                    pools = %self.enabled_pools.display_names(),
                    first_scan_height = scan_floor,
                    blocks_below_birthday,
                    "bootstrap: rebuilt account from keys.toml"
                );
                if let Some(gap) = blocks_below_birthday {
                    if gap > BOOTSTRAP_SCAN_FLOOR_WARN_GAP {
                        warn!(
                            "[{}] bootstrap: scan floor {} is {} blocks below birthday {} - far \
                             below the wallet birthday; the rescan will scan history it need not \
                             (check shard alignment / wallet_birthday)",
                            self.name,
                            scan_floor.unwrap_or(0),
                            gap,
                            birthday
                        );
                    }
                }
                self.update_status();
            }
            Ok(None) => warn!(
                "[{}] bootstrap: account missing immediately after creation",
                self.name
            ),
            Err(e) => warn!(
                "[{}] bootstrap: re-reading the new account failed: {e}",
                self.name
            ),
        }
    }

    fn update_status(&self) {
        // `get_wallet_summary`'s subtree progress estimator can underflow before the chain
        // tip's tree size is known (it panics in debug, wraps in release at this librustzcash
        // rev). Only call it once we have a tip, and isolate it with `catch_unwind` so a
        // progress-estimation panic can never take down the actor.
        let summary = if self.tip_height.is_some() {
            SILENCE_PROGRESS_PANIC.with(|f| f.set(true));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.db_data.get_wallet_summary(self.confirmations_policy)
            }));
            SILENCE_PROGRESS_PANIC.with(|f| f.set(false));
            r.ok().and_then(|r| r.ok()).flatten()
        } else {
            None
        };
        let (fully_scanned, scan_progress, scanning) = match summary {
            Some(s) => {
                let scanned = Some(u32::from(s.fully_scanned_height()));
                let scan = s.progress().scan();
                let denom = *scan.denominator();
                let ratio = if denom == 0 {
                    1.0
                } else {
                    (*scan.numerator() as f64 / denom as f64).clamp(0.0, 1.0)
                };
                (scanned, ratio, ratio < 1.0)
            }
            None => (None, 0.0, true),
        };

        // The enhancement backlog is the work that remains *after* the block scan reaches the tip
        // (memos, full transparent data - see `enhance_step`). While the block scan is still
        // running it dominates readiness via the height gap, so don't pay the extra DB read; once
        // caught up, this count is what stands between "scanned to tip" and "ready to serve full
        // history", so measure it fresh. `0` while scanning means "not yet measured", not "drained".
        let pending_enhancements = if scanning {
            0
        } else {
            self.count_pending_enhancements()
        };

        // `Ready` must mean "ready to serve full history", so a non-empty enhancement backlog keeps
        // the connection in `Syncing` even though the block scan is done - otherwise /status,
        // getpeerinfo and getblockchaininfo would all report caught-up while memos are still
        // missing and history calls lag behind the drain.
        let conn_state = if self.client.is_none() {
            ConnState::Down
        } else if scanning || pending_enhancements > 0 {
            ConnState::Syncing
        } else {
            ConnState::Ready
        };
        // For an encrypted wallet, report the absolute relock time (0 = locked), matching
        // Bitcoin Core's `getwalletinfo.unlocked_until`. Unencrypted wallets report `None`.
        let unlocked_until = self.encrypted.then(|| match self.unlock_until {
            Some(t) => now_unix() + t.saturating_duration_since(Instant::now()).as_secs() as i64,
            None => 0,
        });
        let status = SyncStatus {
            connected: self.client.is_some(),
            server: Some(self.server.describe()),
            conn_state,
            chain_tip: self.tip_height,
            fully_scanned,
            birthday: Some(self.birthday),
            best_block_hash: self.tip_hash.clone(),
            scan_progress,
            scanning,
            pending_enhancements,
            encrypted: self.encrypted,
            watch_only: self.watch_only,
            unlocked_until,
        };
        let _ = self.status_tx.send(status);
    }

    /// Re-broadcast wallet transactions that are still unmined and unexpired, at most once
    /// per `rebroadcast_interval`. Run only when caught up, so a tx that was mined but not
    /// yet scanned isn't pointlessly re-sent. Rejections from a node that already knows the
    /// tx are expected and logged at debug; transport failures drop the client so the next
    /// loop iteration reconnects/fails over.
    async fn maybe_rebroadcast(&mut self) {
        let Some(tip) = self.tip_height else { return };
        if self.client.is_none()
            || self
                .last_rebroadcast
                .is_some_and(|t| t.elapsed() < self.rebroadcast_interval)
        {
            return;
        }
        self.last_rebroadcast = Some(Instant::now());
        // Same caught-up cadence: drop first-seen entries for txs that have since mined.
        self.prune_first_seen();
        let txs = match read::unmined_raw_txs(&self.wallet_dir, tip) {
            Ok(txs) => txs,
            Err(e) => {
                warn!("[{}] querying unmined txs for rebroadcast: {e}", self.name);
                return;
            }
        };
        for (txid, data) in txs {
            let Some(client) = self.client.as_mut() else {
                return;
            };
            let sent = tokio::time::timeout(UNARY_RPC_TIMEOUT, client.broadcast_tx(data))
                .await
                .map_err(|_| anyhow!("rebroadcast timed out after {UNARY_RPC_TIMEOUT:?}"))
                .and_then(|r| r);
            match sent {
                Ok(outcome) => {
                    if outcome.is_accepted() {
                        info!("[{}] re-broadcast unmined tx {txid}", self.name);
                    } else {
                        tracing::debug!(
                            "[{}] rebroadcast of {txid} rejected (code {}): {}",
                            self.name,
                            outcome.error_code,
                            outcome.error_message
                        );
                    }
                }
                Err(e) => {
                    self.mark_disconnected(format!("rebroadcast transport error: {e}"));
                    self.update_status();
                    return;
                }
            }
        }
    }

    /// Returns `true` if the actor should stop.
    async fn handle_command(&mut self, cmd: WalletCommand) -> bool {
        match cmd {
            WalletCommand::GetNewAddress { receivers, reply } => {
                let res = self.get_new_address(receivers);
                let _ = reply.send(res);
            }
            WalletCommand::GetAddressForAccount {
                receivers,
                diversifier_index,
                reply,
            } => {
                let res = self.get_address_for_account(receivers, diversifier_index);
                let _ = reply.send(res);
            }
            WalletCommand::Send {
                request,
                confirmations,
                privacy,
                reply,
            } => {
                self.begin_or_queue_send(request, confirmations, privacy, reply)
                    .await;
            }
            WalletCommand::GetRawTx { txid, reply } => {
                let res = self.do_get_raw_tx(txid).await;
                let _ = reply.send(res);
            }
            WalletCommand::Broadcast { data, reply } => {
                let res = self.do_broadcast(data).await;
                let _ = reply.send(res);
            }
            WalletCommand::Unlock {
                passphrase,
                timeout_secs,
                reply,
            } => {
                let res = self.do_unlock(passphrase, timeout_secs).await;
                let _ = reply.send(res);
            }
            WalletCommand::Lock { reply } => {
                let res = self.do_lock();
                let _ = reply.send(res);
            }
        }
        false
    }

    /// Relock an encrypted wallet whose `walletpassphrase` timeout has elapsed: zeroize the
    /// in-memory seed and clear the deadline. Cheap and idempotent.
    fn relock_if_expired(&mut self) {
        if self.unlock_until.is_some_and(|t| Instant::now() >= t) {
            seed_guard(&self.seed).lock();
            self.unlock_until = None;
            info!(
                "[{}] wallet auto-locked (walletpassphrase timeout elapsed)",
                self.name
            );
            self.update_status();
        }
    }

    /// The wallet's account id, or [`account_not_ready`] while a bootstrap is still pending.
    fn require_account(&self) -> Result<AccountUuid, RpcError> {
        self.account_id.ok_or_else(account_not_ready)
    }

    fn get_new_address(&mut self, receivers: Option<PoolSet>) -> Result<String, RpcError> {
        // No override → the wallet's configured default receivers. An override must be a subset
        // of the wallet's enabled pools (the RPC layer also validates this, but the actor is the
        // authority on the wallet's configuration, so re-check here).
        let receivers = match receivers {
            Some(set) => {
                if !set.is_subset_of(&self.enabled_pools) {
                    return Err(RpcError::invalid_parameter(format!(
                        "requested receivers ({}) include a pool not enabled on this wallet ({})",
                        set.display_names(),
                        self.enabled_pools.display_names()
                    )));
                }
                set
            }
            None => self.default_receivers.clone(),
        };
        let account_id = self.require_account()?;
        let request = receivers.to_unified_address_request();
        let (ua, _) = self
            .db_data
            .get_next_available_address(account_id, request)
            .map_err(|e| RpcError::wallet(format!("address generation failed: {e}")))?
            .ok_or_else(|| {
                RpcError::wallet(format!(
                    "no address available for account with receivers ({}); the account's viewing \
                     key may not support all requested pools",
                    receivers.display_names()
                ))
            })?;
        let encoded = ua.encode(&self.network);
        Ok(encoded)
    }

    /// Derive a Unified Address for this wallet's account, backing `z_getaddressforaccount`.
    /// With `diversifier_index = Some(j)` it derives at exactly that index (re-deriving an
    /// already-exposed index returns the same address; requesting a different receiver set at an
    /// exposed index is a reuse error); with `None` it picks the next unused index, exactly like
    /// `get_new_address`. `receivers` has already been validated against the enabled pools.
    /// Returns the encoded UA plus the diversifier index actually used (as a `u128`).
    fn get_address_for_account(
        &mut self,
        receivers: PoolSet,
        diversifier_index: Option<DiversifierIndex>,
    ) -> Result<(String, u128), RpcError> {
        let account_id = self.require_account()?;
        let request = receivers.to_unified_address_request();
        let (ua, j) = match diversifier_index {
            None => self
                .db_data
                .get_next_available_address(account_id, request)
                .map_err(|e| RpcError::wallet(format!("address generation failed: {e}")))?
                .ok_or_else(|| {
                    RpcError::wallet(format!(
                        "no address available for account with receivers ({}); the account's \
                         viewing key may not support all requested pools",
                        receivers.display_names()
                    ))
                })?,
            Some(j) => {
                let ua = self
                    .db_data
                    .get_address_for_index(account_id, j, request)
                    .map_err(map_address_for_index_error)?
                    // librustzcash returns `Ok(None)` when no address can be derived at this
                    // index for the requested receivers (e.g. an invalid Sapling diversifier).
                    .ok_or_else(|| {
                        RpcError::wallet(format!(
                            "Error: no address at diversifier index {}.",
                            u128::from(j)
                        ))
                    })?;
                (ua, j)
            }
        };
        Ok((ua.encode(&self.network), u128::from(j)))
    }

    /// Best-effort catch-up sync run once before each spend so the transaction is built
    /// against zebra's real chain tip (see the call site in `do_send`).
    ///
    /// librustzcash derives a transaction's target height - and thus its expiry (target +
    /// expiry delta) - from the wallet DB's chain tip, so a spend built while that tip lags
    /// zebra's real tip by more than the expiry delta lands already-expired and zebra rejects
    /// it with -25. It is NOT enough to just bump the DB chain tip, though: librustzcash also
    /// derives the spend *anchor* (target − confirmations) from the same tip, and its
    /// spendability check zeroes the entire shielded balance when the anchor falls in a range
    /// that hasn't been scanned (`zcash_client_sqlite`'s `get_wallet_summary`). So we must pull
    /// the tip in *and* scan up to it: refresh the tip (records zebra's real tip, extending the
    /// scan queue), then drive `sync_step` until caught up, leaving no unscanned range below the
    /// anchor. After this, both the expiry and the anchor are valid.
    ///
    /// Normally the actor's sync loop already keeps the wallet caught up, so this is a no-op
    /// (one latest-block RPC, then a `sync_step` that reports no work). Only when the loop has
    /// starved under load - the case that produced the intermittent -25 - does it actually scan
    /// a gap here, on the actor thread it already holds for the send. The catch-up loop targets
    /// the tip captured by `refresh_tip` (it isn't re-bumped mid-loop), so newly-mined blocks
    /// can't make it spin; it terminates once that tip is scanned.
    ///
    /// Best-effort throughout: an unreachable upstream or a sync error logs and falls back to
    /// the last-scanned tip (the send then rides the usual commit/rebroadcast path, and would
    /// fail at broadcast anyway if the upstream is truly gone), so this must never hard-fail the
    /// spend.
    async fn sync_to_tip_for_send(&mut self) {
        if self.client.is_none() {
            if let Err(e) = self.connect().await {
                warn!(
                    "[{}] could not reach upstream to sync before sending ({e}); building \
                     against the last-scanned height",
                    self.name
                );
                return;
            }
        }
        // Record zebra's real tip (and extend the scan queue up to it).
        if let Err(e) = self.refresh_tip().await {
            // A failed refresh means the client is likely stale; drop it so the broadcast
            // path reconnects cleanly, and build against the last-scanned tip.
            self.mark_disconnected(format!("tip refresh before send failed ({e})"));
            return;
        }
        // Scan up to that tip so the spend anchor lands in a fully-scanned range. Bounded: the
        // target is the tip just captured, so the loop ends when the wallet reaches it.
        loop {
            match self.sync_step().await {
                Ok(true) => continue,
                Ok(false) => break,
                Err(e) => {
                    self.mark_disconnected(format!("sync before send failed ({e})"));
                    break;
                }
            }
        }
    }

    /// Whether sends on this wallet use the cached-Orchard PCZT path (so prove and store are
    /// separable). True for the default Orchard-only wallet with `cache_proving_key` on. A
    /// Sapling-spending wallet (or `cache_proving_key` off) uses the fused path, which has no
    /// prove/store seam - see [`Self::do_send_fused`].
    fn cached_pczt_path(&self) -> bool {
        self.orchard_keys.is_some() && !self.enabled_pools.contains(Pool::Sapling)
    }

    /// Whether a send should be pipelined: `[spend] pipeline_proving` on *and* the cached PCZT
    /// path applies (only that path can prove off the actor and store back on it).
    fn pipeline_eligible(&self) -> bool {
        self.pipeline_proving && self.cached_pczt_path()
    }

    /// Phase A (note selection + PCZT build), on the actor. Selects inputs with the greedy
    /// selector + ZIP-317 change strategy, enforces the privacy / Orchard-action policies on the
    /// built proposal, then builds the (unproven, `Send`-able) PCZT. A DB read - milliseconds even
    /// on a large wallet - so it stays on the single writer. Returns the PCZT plus the send's
    /// shape and how long phase A took, for the latency log line.
    fn build_proposal_and_pczt(
        &mut self,
        request: TransactionRequest,
        policy: ConfirmationsPolicy,
        privacy: SendPrivacy,
    ) -> Result<(pczt::Pczt, SendShape, Duration), RpcError> {
        let account_id = self.require_account()?;
        let net = self.network;
        let change_pool = self.enabled_pools.change_pool();
        let orchard_action_limit = self.orchard_action_limit;
        let db = &mut self.db_data;
        tokio::task::block_in_place(move || -> Result<_, RpcError> {
            let start = Instant::now();
            let change_strategy = MultiOutputChangeStrategy::new(
                StandardFeeRule::Zip317,
                None,
                change_pool,
                DustOutputPolicy::default(),
                SplitPolicy::with_min_output_value(
                    NonZeroUsize::new(TARGET_NOTE_COUNT).expect("nonzero"),
                    Zatoshis::from_u64(MIN_SPLIT_OUTPUT_VALUE).expect("valid"),
                ),
            );
            let input_selector = GreedyInputSelector::new();
            let proposal = propose_transfer(
                db,
                &net,
                account_id,
                &input_selector,
                &change_strategy,
                request,
                policy,
                None,
            )
            .map_err(|e| enrich_insufficient_funds(db, policy, classify_err(e)))?;
            if privacy == SendPrivacy::FullPrivacy {
                enforce_full_privacy(&proposal)?;
            }
            enforce_orchard_action_limit(&proposal, orchard_action_limit)?;
            let shape = proposal_shape(&proposal);
            let pczt = create_pczt_from_proposal::<_, _, Infallible, _, Infallible, _>(
                db,
                &net,
                account_id,
                OvkPolicy::Sender,
                &proposal,
            )
            .map_err(|e| enrich_insufficient_funds(db, policy, classify_pczt_err(e)))?;
            Ok((pczt, shape, start.elapsed()))
        })
    }

    /// Build, prove, and broadcast a send inline (today's behaviour): the whole of phase A→C runs
    /// on the actor under `block_in_place`, so the actor (and thus sync) is blocked for the whole
    /// proof. `[spend] pipeline_proving` moves the proof off the actor - see
    /// [`Self::begin_or_queue_send`]. Used directly when pipelining is disabled or ineligible.
    async fn do_send(
        &mut self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
        privacy: SendPrivacy,
    ) -> Result<TxId, RpcError> {
        // Hard backstop: if an encrypted wallet's unlock has expired but proactive relock
        // hasn't fired yet (e.g. a long sync batch was in progress), lock now so the spend
        // can't slip through past its timeout. `derive_usk` then returns -13 as expected.
        self.relock_if_expired();

        // Catch up to zebra's real chain tip before building the spend, so the transaction's
        // target height - and therefore its expiry (target + expiry delta) - is computed
        // against the real tip rather than zecd's last-scanned height, which can lag it under
        // load and produce an already-expired tx that zebra rejects with -25. This scans up to
        // the tip (not just bumps the pointer) so the spend anchor also lands in a fully-scanned
        // range; normally a no-op because the sync loop keeps the wallet caught up.
        self.sync_to_tip_for_send().await;

        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        // Lock the shared seed only long enough to derive the spending key; the guard is released
        // before the (long) proving below, so a concurrent `walletlock` fast path can zeroize the
        // resident seed while this send proves with its already-derived local USK.
        let usk = seed_guard(&self.seed).derive_usk(self.network, account_index)?;
        // A per-call `minconf` (z_sendmany) overrides the wallet-wide policy for this send's
        // note selection; the synchronous sends pass `None` and use the configured policy.
        let policy = confirmations.unwrap_or(self.confirmations_policy);

        if !self.cached_pczt_path() {
            return self.do_send_fused(usk, request, policy, privacy).await;
        }

        // Cached-Orchard PCZT path: phase A (select+build) → phase B (prove+sign) → phase C
        // (store), all on the actor. Each phase is timed so the send-latency log shows where the
        // cost lands on a large, note-fragmented wallet.
        let (pczt, shape, build) = self.build_proposal_and_pczt(request, policy, privacy)?;
        let keys = self.orchard_keys.clone().expect("cached path");
        let prover = self.prover.clone();
        let db = &mut self.db_data;
        let (txid, raw, prove, store): (TxId, Vec<u8>, Duration, Duration) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let p0 = Instant::now();
                let signed = prove_sign_pczt(pczt, &usk, &prover, &keys)?;
                let prove = p0.elapsed();
                let s0 = Instant::now();
                let txid = store_pczt(db, signed, &keys)?;
                let raw = read_raw_tx(db, txid)?;
                Ok((txid, raw, prove, s0.elapsed()))
            })?;

        let b0 = Instant::now();
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        log_send_latency(
            &self.name,
            "inline",
            shape,
            build,
            prove,
            store,
            b0.elapsed(),
        );
        Ok(txid)
    }

    /// The legacy fused send path: librustzcash's `create_proposed_transactions` builds, proves,
    /// and stores under one `&mut` (rebuilding the proving key per send). Used by a Sapling-
    /// spending wallet (the PCZT path here signs only Orchard spends) or when
    /// `cache_proving_key` is off. Not pipelined - there is no prove/store seam to split.
    async fn do_send_fused(
        &mut self,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        request: TransactionRequest,
        policy: ConfirmationsPolicy,
        privacy: SendPrivacy,
    ) -> Result<TxId, RpcError> {
        let net = self.network;
        let change_pool = self.enabled_pools.change_pool();
        let orchard_action_limit = self.orchard_action_limit;
        let account_id = self.require_account()?;
        let prover: &LocalTxProver = &self.prover;
        let db = &mut self.db_data;
        let (txid, raw, shape, build, prove): (TxId, Vec<u8>, SendShape, Duration, Duration) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let start = Instant::now();
                let change_strategy = MultiOutputChangeStrategy::new(
                    StandardFeeRule::Zip317,
                    None,
                    change_pool,
                    DustOutputPolicy::default(),
                    SplitPolicy::with_min_output_value(
                        NonZeroUsize::new(TARGET_NOTE_COUNT).expect("nonzero"),
                        Zatoshis::from_u64(MIN_SPLIT_OUTPUT_VALUE).expect("valid"),
                    ),
                );
                let input_selector = GreedyInputSelector::new();
                let proposal = propose_transfer(
                    db,
                    &net,
                    account_id,
                    &input_selector,
                    &change_strategy,
                    request,
                    policy,
                    None,
                )
                .map_err(|e| enrich_insufficient_funds(db, policy, classify_err(e)))?;
                if privacy == SendPrivacy::FullPrivacy {
                    enforce_full_privacy(&proposal)?;
                }
                enforce_orchard_action_limit(&proposal, orchard_action_limit)?;
                let shape = proposal_shape(&proposal);
                let build = start.elapsed();
                let p0 = Instant::now();
                let txids = create_proposed_transactions(
                    db,
                    &net,
                    prover,
                    prover,
                    &SpendingKeys::from_unified_spending_key(usk),
                    OvkPolicy::Sender,
                    &proposal,
                    None,
                )
                .map_err(|e| enrich_insufficient_funds(db, policy, classify_err(e)))?;
                if txids.len() > 1 {
                    return Err(RpcError::wallet(
                        "multi-transaction proposals are not supported",
                    ));
                }
                let txid = *txids.first();
                let raw = read_raw_tx(db, txid)?;
                Ok((txid, raw, shape, build, p0.elapsed()))
            })?;

        let b0 = Instant::now();
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        log_send_latency(
            &self.name,
            "fused",
            shape,
            build,
            prove,
            Duration::ZERO,
            b0.elapsed(),
        );
        Ok(txid)
    }

    /// Entry point for a `Send` command. Runs inline (today's behaviour) unless pipelining is
    /// eligible, in which case the proof runs off the actor so sync stays live. Pipelined sends
    /// stay serialized: only one PCZT is uncommitted at a time (no double-spend surface, no
    /// reservation overlay), so a send arriving while a proof is in flight is queued and started
    /// once the in-flight one commits.
    async fn begin_or_queue_send(
        &mut self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
        privacy: SendPrivacy,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    ) {
        if !self.pipeline_eligible() {
            let res = self.do_send(request, confirmations, privacy).await;
            let _ = reply.send(res);
            return;
        }
        if self.send_in_flight {
            if self.send_queue.len() >= MAX_QUEUED_SENDS {
                let _ = reply.send(Err(RpcError::wallet(format!(
                    "too many sends queued behind an in-flight proof ({MAX_QUEUED_SENDS}); \
                     retry shortly"
                ))));
                return;
            }
            self.send_queue.push_back(PendingSend {
                request,
                confirmations,
                privacy,
                reply,
            });
            return;
        }
        self.start_pipelined_send(request, confirmations, privacy, reply)
            .await;
    }

    /// Start a pipelined send: do phase A on the actor, then hand phase B (prove+sign) to a
    /// blocking thread and return to the loop. On a phase-A failure the caller is replied to here
    /// and `send_in_flight` is left clear (the queue is pumped by the caller). On success
    /// `send_in_flight` is set and the completion arrives later via `send_done_tx`.
    async fn start_pipelined_send(
        &mut self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
        privacy: SendPrivacy,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    ) {
        self.relock_if_expired();

        // Catch up to zebra's real chain tip before phase A builds the proposal, so the
        // transaction's target/expiry height and spend anchor are computed against the real tip
        // rather than zecd's last-scanned height (which lags under load, producing an
        // already-expired -25). Mirrors the call in `do_send` for the non-pipelined path; a
        // no-op when the sync loop already has the wallet caught up. Runs here (not in
        // `begin_or_queue_send`) so a send queued behind an in-flight proof re-syncs when it
        // actually starts, keeping its tip fresh.
        self.sync_to_tip_for_send().await;

        let account_index = match self.account_index.ok_or_else(private_keys_disabled) {
            Ok(i) => i,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        // Lock the shared seed only long enough to derive the spending key; the guard is released
        // before the (long) proving below, so a concurrent `walletlock` fast path can zeroize the
        // resident seed while this send proves with its already-derived local USK.
        let usk = match seed_guard(&self.seed).derive_usk(self.network, account_index) {
            Ok(u) => u,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let policy = confirmations.unwrap_or(self.confirmations_policy);
        let (pczt, shape, build) = match self.build_proposal_and_pczt(request, policy, privacy) {
            Ok(v) => v,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };

        let prover = self.prover.clone();
        let keys = self
            .orchard_keys
            .clone()
            .expect("pipeline requires cached keys");
        let done_tx = self.send_done_tx.clone();
        let name = self.name.clone();
        self.send_in_flight = true;
        tokio::task::spawn_blocking(move || {
            let p0 = Instant::now();
            // Isolate a proving panic: a completion MUST always be sent, or the pipeline would
            // wedge with `send_in_flight` stuck true.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_sign_pczt(pczt, &usk, &prover, &keys)
            }))
            .unwrap_or_else(|_| {
                error!("[{name}] send proof panicked off-actor; the actor continues");
                Err(RpcError::wallet("proving panicked"))
            });
            let _ = done_tx.blocking_send(SendCompletion {
                result,
                policy,
                shape,
                build_elapsed: build,
                prove_elapsed: p0.elapsed(),
                reply,
            });
            // `usk` is dropped (zeroized) here.
        });
    }

    /// Start the next queued send, draining sends whose phase A fails immediately so the queue
    /// keeps moving. Stops once a send is in flight (its proof started) or the queue is empty.
    async fn pump_send_queue(&mut self) {
        while !self.send_in_flight {
            let Some(p) = self.send_queue.pop_front() else {
                break;
            };
            self.start_pipelined_send(p.request, p.confirmations, p.privacy, p.reply)
                .await;
        }
    }

    /// Phase C of a pipelined send, on the actor: store the proven tx (marking inputs spent),
    /// reply to the caller, and broadcast. Clears `send_in_flight` first so a panic mid-commit
    /// can't wedge the pipeline (the loop pumps the queue afterwards).
    async fn finish_send(&mut self, done: SendCompletion) {
        self.send_in_flight = false;
        let SendCompletion {
            result,
            policy,
            shape,
            build_elapsed,
            prove_elapsed,
            reply,
        } = done;
        let outcome = match result {
            Err(e) => Err(e),
            Ok(signed) => {
                self.store_and_broadcast(signed, policy, shape, build_elapsed, prove_elapsed)
                    .await
            }
        };
        let _ = reply.send(outcome);
    }

    /// Store + broadcast a proven PCZT (phase C body). Storing marks the send's inputs spent in
    /// the DB (the authoritative spend record from here on); broadcast is best-effort and rides
    /// the rebroadcast loop on failure, like the inline path.
    async fn store_and_broadcast(
        &mut self,
        signed: pczt::Pczt,
        policy: ConfirmationsPolicy,
        shape: SendShape,
        build: Duration,
        prove: Duration,
    ) -> Result<TxId, RpcError> {
        let keys = self
            .orchard_keys
            .clone()
            .expect("pipeline requires cached keys");
        let db = &mut self.db_data;
        let _ = policy; // store rarely surfaces -6; kept for symmetry with the inline path.
        let (txid, raw, store): (TxId, Vec<u8>, Duration) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let s0 = Instant::now();
                let txid = store_pczt(db, signed, &keys)?;
                let raw = read_raw_tx(db, txid)?;
                Ok((txid, raw, s0.elapsed()))
            })?;
        let b0 = Instant::now();
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        log_send_latency(
            &self.name,
            "pipelined",
            shape,
            build,
            prove,
            store,
            b0.elapsed(),
        );
        Ok(txid)
    }

    /// Run [`finish_send`](Self::finish_send) under panic isolation, then pump the send queue.
    /// Mirrors [`handle_command_caught`](Self::handle_command_caught): a panic on the commit path
    /// must not take the actor (and every wallet write) down. `send_in_flight` is already cleared
    /// inside `finish_send`, so the queue can always make progress afterwards.
    async fn finish_send_caught(&mut self, done: SendCompletion) {
        use futures_util::FutureExt as _;
        if std::panic::AssertUnwindSafe(self.finish_send(done))
            .catch_unwind()
            .await
            .is_err()
        {
            error!(
                "[{}] pipelined send commit panicked; the actor continues (this is a bug - \
                 please report it)",
                self.name
            );
            self.send_in_flight = false;
        }
        self.pump_send_queue().await;
    }

    /// Broadcast a transaction that is already committed to the wallet DB (its inputs are
    /// locked until expiry) and that `maybe_rebroadcast` keeps re-submitting while it is
    /// unmined and unexpired. A transport-level failure must NOT surface as an error:
    /// bitcoind's contract is that once the wallet has committed the tx, the call returns
    /// the txid even if initial relay fails - an error would invite the caller to retry the
    /// payment while the original can still be re-broadcast and confirm (an
    /// application-level double-pay). Only an explicit upstream rejection (the node examined
    /// the tx and refused it) is surfaced, as -26; the tx's inputs stay locked until its
    /// expiry height, after which they become spendable again - an immediate retry fails
    /// with -6 rather than double-paying.
    async fn broadcast_committed(&mut self, txid: TxId, raw: Vec<u8>) -> Result<(), RpcError> {
        if self.client.is_none() {
            if let Err(e) = self.connect().await {
                warn!(
                    "[{}] created {txid} but no upstream is reachable ({e}); it will be \
                     re-broadcast once a connection recovers",
                    self.name
                );
                return Ok(());
            }
        }
        let response = {
            let client = self.client.as_mut().expect("connected above");
            // Bounded: a peer that hangs mid-broadcast is treated like any other transport
            // failure - the committed tx rides on the rebroadcast loop either way.
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.broadcast_tx(raw))
                .await
                .map_err(|_| anyhow!("broadcast timed out after {UNARY_RPC_TIMEOUT:?}"))
                .and_then(|r| r)
        };
        let outcome = match response {
            Ok(outcome) => outcome,
            Err(e) => {
                // Transport failure: drop the dead client so the next op reconnects/fails over.
                // The committed tx rides on the rebroadcast loop.
                self.mark_disconnected(format!(
                    "broadcast of {txid} failed in transport ({e}); it will be re-broadcast"
                ));
                self.update_status();
                return Ok(());
            }
        };
        if !outcome.is_accepted() {
            // The node already holding this exact tx (a rebroadcast raced an earlier
            // delivery, or it even mined already) means the committed send IS delivered -
            // success, not a rejection.
            if upstream_already_has_tx(&outcome.error_message) != AlreadyKnown::No {
                info!(
                    "[{}] upstream already has {txid}; treating broadcast as delivered",
                    self.name
                );
                return Ok(());
            }
            // An explicit upstream rejection (the node examined the tx and refused it) is a
            // different case from a transport failure: surface it as -26. The tx's notes stay
            // locked in the wallet until its expiry height, after which they become spendable
            // again - an immediate retry fails with -6 rather than double-paying.
            let reason = sanitize_upstream_msg(&outcome.error_message);
            warn!(
                "[{}] upstream rejected {txid} (code {}): {reason}",
                self.name, outcome.error_code
            );
            return Err(RpcError::new(
                codes::RPC_VERIFY_REJECTED,
                format!(
                    "transaction rejected (code {}): {reason}",
                    outcome.error_code
                ),
            ));
        }
        Ok(())
    }

    /// Return raw transaction bytes: prefer the locally-stored copy (present for txs we
    /// created or have enhanced), otherwise fetch the full tx from the upstream. "Upstream
    /// doesn't know the txid" is an application-level miss encoded as `Ok(None)` by the
    /// backend (so the healthy connection is kept); only transport failures drop the client.
    async fn do_get_raw_tx(&mut self, txid: TxId) -> Result<Option<RawTx>, RpcError> {
        if let Ok(Some(tx)) = self.db_data.get_transaction(txid) {
            let mut buf = Vec::new();
            tx.write(&mut buf)
                .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;
            return Ok(Some(RawTx {
                data: buf,
                mined_height: None,
            }));
        }
        self.fetch_tx_from_upstream(txid).await
    }

    /// Fetch a full transaction from lightwalletd by txid (the chain's view, never the local
    /// copy - used both by `do_get_raw_tx` and by transaction-data-request servicing). The
    /// `TxFilter` hash is the txid's internal bytes (per zcash-devtool's enhance).
    async fn fetch_tx_from_upstream(&mut self, txid: TxId) -> Result<Option<RawTx>, RpcError> {
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to upstream: {e}")))?;
        }
        let fetched = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| RpcError::misc("not connected to upstream"))?;
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.fetch_tx(txid))
                .await
                .map_err(|_| anyhow!("fetch_tx timed out after {UNARY_RPC_TIMEOUT:?}"))
                .and_then(|r| r)
        };
        match fetched {
            Ok(found) => Ok(found.map(|tx| RawTx {
                data: tx.data,
                mined_height: tx.mined_height,
            })),
            Err(e) => {
                // Transport failure: drop the dead client so the next op reconnects/fails over.
                self.mark_disconnected(format!("transaction fetch failed: {e}"));
                self.update_status();
                Err(RpcError::misc(format!("transaction fetch failed: {e}")))
            }
        }
    }

    /// Broadcast caller-supplied raw transaction bytes (`sendrawtransaction`). Unlike
    /// `do_send`, the transaction is not in our wallet DB, so there is no rebroadcast loop
    /// backing it - every failure (transport or rejection) surfaces as an error so the
    /// caller knows the network never accepted the tx.
    async fn do_broadcast(&mut self, data: Vec<u8>) -> Result<(), RpcError> {
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to upstream: {e}")))?;
        }
        let response = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| RpcError::misc("not connected to upstream"))?;
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.broadcast_tx(data))
                .await
                .map_err(|_| anyhow!("broadcast timed out after {UNARY_RPC_TIMEOUT:?}"))
                .and_then(|r| r)
        };
        let outcome = match response {
            Ok(outcome) => outcome,
            Err(e) => {
                // Transport/deadline failure: drop the client so the next op reconnects/fails over.
                self.mark_disconnected(format!("transaction broadcast failed: {e}"));
                self.update_status();
                return Err(RpcError::misc(format!("transaction broadcast failed: {e}")));
            }
        };
        let result = classify_broadcast_outcome(&outcome);
        match &result {
            // Accepted-but-not-fresh is the idempotent already-in-mempool case (worth a note).
            Ok(()) if !outcome.is_accepted() => info!(
                "[{}] upstream already has tx in mempool; sendrawtransaction succeeds",
                self.name
            ),
            Err(e) if e.code == codes::RPC_VERIFY_REJECTED => warn!(
                "[{}] upstream rejected tx (code {}): {}",
                self.name, outcome.error_code, e.message
            ),
            _ => {}
        }
        result
    }

    /// `walletpassphrase`: decrypt the seed with `passphrase` and hold it unlocked until
    /// `timeout_secs` from now (argument validation/clamping happens in the RPC layer). Only
    /// valid for an encrypted wallet; an unencrypted one returns -15 like Bitcoin Core.
    async fn do_unlock(
        &mut self,
        passphrase: store::Passphrase,
        timeout_secs: i64,
    ) -> Result<(), RpcError> {
        if !self.encrypted {
            return Err(RpcError::new(
                codes::RPC_WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletpassphrase was called.",
            ));
        }
        let st = store::WalletStore::read(&self.keys_path)
            .map_err(|e| RpcError::wallet(format!("reading keys.toml: {e}")))?;
        // scrypt is deliberately slow (~1s at the default work factor); run it under
        // `block_in_place` so it doesn't stall the async runtime (the proving pattern).
        let seed = tokio::task::block_in_place(|| st.decrypt_seed_with_passphrase(passphrase))
            // Any decryption failure on the passphrase path means the passphrase was wrong.
            .map_err(|_| {
                RpcError::new(
                    codes::RPC_WALLET_PASSPHRASE_INCORRECT,
                    "Error: The wallet passphrase entered was incorrect.",
                )
            })?
            .ok_or_else(|| RpcError::wallet("wallet has no stored seed"))?;
        seed_guard(&self.seed).set(seed);
        // Re-running walletpassphrase overwrites the deadline (resets the timer). A timeout of 0
        // relocks ~immediately, which `relock_if_expired` then enforces.
        self.unlock_until = Some(Instant::now() + Duration::from_secs(timeout_secs.max(0) as u64));
        self.relock_if_expired();
        // First unlock of an encrypted wallet on an empty data directory: now that the seed is
        // available, rebuild the account from keys.toml right away (best-effort; if the upstream
        // isn't connected yet the regular sync loop retries). Skipped if the timeout was 0 (the
        // seed was just relocked) or no bootstrap is pending.
        if self.pending_bootstrap.is_some() && seed_guard(&self.seed).is_unlocked() {
            self.maybe_bootstrap_account().await;
        }
        self.update_status();
        Ok(())
    }

    /// `walletlock`: zeroize the seed and cancel the pending relock. -15 if unencrypted.
    fn do_lock(&mut self) -> Result<(), RpcError> {
        if !self.encrypted {
            return Err(RpcError::new(
                codes::RPC_WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletlock was called.",
            ));
        }
        seed_guard(&self.seed).lock();
        self.unlock_until = None;
        self.update_status();
        Ok(())
    }
}

/// Ensure a freshly-connected upstream `client` is healthy, serves the chain this wallet
/// is configured for, and the wallet has its note-commitment subtree roots. The
/// `server_info` call doubles as the liveness probe and the wrong-chain guard (a mainnet
/// zecd pointed at a testnet upstream would otherwise happily scan the wrong chain). The
/// first successful call this process additionally downloads the subtree roots and sets
/// `roots_synced`; the roots persist in the wallet DB, so they aren't re-streamed on each
/// reconnect / primary re-probe.
///
/// The whole check is bounded by `budget`: a peer that accepts connections but never answers
/// (the dial timeout can't see this) must not stall the actor's command loop.
async fn prepare_client<C: ChainSource>(
    client: &mut C,
    db_data: &mut WriteDb,
    network: ZNetwork,
    roots_synced: &mut bool,
    budget: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(budget, async {
        verify_server_network(client, network).await?;
        if !*roots_synced {
            engine::update_subtree_roots(client, db_data).await?;
            *roots_synced = true;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("upstream health check timed out after {budget:?}"))?
}

/// Refuse an upstream whose `chain_name` contradicts the configured network. Only the
/// mainnet/non-mainnet boundary is enforced: zebra reports `"test"` for regtest too (its
/// `bip70_network_name` only distinguishes mainnet), so test vs regtest cannot be told
/// apart from here - and the guard's job is ensuring a mainnet wallet never scans a test
/// chain (or vice versa). A definitive cross is a hard error so the caller fails over to
/// the next candidate; an unrecognized name is only a warning, since not every server
/// reports one.
async fn verify_server_network<C: ChainSource>(
    client: &mut C,
    network: ZNetwork,
) -> anyhow::Result<()> {
    let info = client.server_info().await?;
    match chain_name_is_main(&info.chain_name) {
        Some(server_is_main) => {
            let wallet_is_main = matches!(network, ZNetwork::Main);
            if server_is_main != wallet_is_main {
                return Err(anyhow!(
                    "lightwalletd serves chain '{}' but this wallet is configured for '{}'",
                    info.chain_name,
                    network.name()
                ));
            }
        }
        None => warn!(
            "lightwalletd reported unrecognized chain_name {:?}; skipping network check",
            info.chain_name
        ),
    }
    Ok(())
}

/// Classify a lightwalletd `chain_name` as mainnet (`Some(true)`), a test chain
/// (`Some(false)`), or unrecognized (`None`).
fn chain_name_is_main(chain_name: &str) -> Option<bool> {
    match chain_name {
        "main" => Some(true),
        "test" | "regtest" => Some(false),
        _ => None,
    }
}

/// Bound an upstream-supplied string before echoing it into an RPC error. Upstream
/// reject reasons are genuinely useful to clients (Bitcoin Core relays its own), but the
/// upstream is only operator-trusted, so strip control characters and cap the length rather
/// than relay arbitrary bytes (the same bounded text is what call sites log).
fn sanitize_upstream_msg(msg: &str) -> String {
    const MAX: usize = 200;
    let mut out: String = msg.chars().filter(|c| !c.is_control()).take(MAX).collect();
    if msg.chars().filter(|c| !c.is_control()).nth(MAX).is_some() {
        out.push('…');
    }
    out
}

/// Classify an upstream broadcast rejection that means the node *already has* this exact
/// transaction. zebra/zcashd reject a resubmission ("transaction already exists in mempool",
/// "txn-already-in-mempool", "txn-already-known", "transaction already in block chain")
/// where Bitcoin Core's `sendrawtransaction` is idempotent (node/transaction.cpp
/// `BroadcastTransaction`): already-in-mempool returns the txid as success, already-mined is
/// `-27` `ALREADY_IN_UTXO_SET`. Matters in practice because zecd's own rebroadcast loop can
/// race a manual `sendrawtransaction` of the same committed tx.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AlreadyKnown {
    No,
    InMempool,
    InChain,
}

fn upstream_already_has_tx(msg: &str) -> AlreadyKnown {
    let m = msg.to_ascii_lowercase();
    if !m.contains("already") {
        return AlreadyKnown::No;
    }
    if m.contains("mempool") || m.contains("known") {
        AlreadyKnown::InMempool
    } else if m.contains("chain") || m.contains("in state") {
        AlreadyKnown::InChain
    } else {
        AlreadyKnown::No
    }
}

/// Map an upstream broadcast verdict onto Bitcoin Core's `sendrawtransaction` contract:
/// an accepted tx - or one the node already holds in its mempool (idempotent resubmission) -
/// is success; an already-mined tx is `-27` `ALREADY_IN_UTXO_SET`; any other rejection is
/// `-26` `RPC_VERIFY_REJECTED` carrying the upstream's (bounded, sanitized) reason. Pure so
/// the code mapping is unit-testable; the caller handles transport failures and logging.
fn classify_broadcast_outcome(outcome: &BroadcastOutcome) -> Result<(), RpcError> {
    if outcome.is_accepted() {
        return Ok(());
    }
    match upstream_already_has_tx(&outcome.error_message) {
        // Already in the mempool: zecd's own rebroadcast loop can race a manual resubmission
        // of the same committed send, so this is success (as in Bitcoin Core).
        AlreadyKnown::InMempool => Ok(()),
        // Already mined: Bitcoin Core's TransactionError::ALREADY_IN_UTXO_SET maps to
        // RPC_VERIFY_ALREADY_IN_UTXO_SET with this exact default message
        // (common/messages.cpp TransactionErrorString).
        AlreadyKnown::InChain => Err(RpcError::new(
            codes::RPC_VERIFY_ALREADY_IN_UTXO_SET,
            "Transaction outputs already in utxo set",
        )),
        AlreadyKnown::No => Err(RpcError::new(
            codes::RPC_VERIFY_REJECTED,
            format!(
                "transaction rejected (code {}): {}",
                outcome.error_code,
                sanitize_upstream_msg(&outcome.error_message)
            ),
        )),
    }
}

/// Await the next message on an open mempool stream, or pend forever when none is open, so
/// the actor's idle `select!` arm simply never fires without a subscription.
async fn mempool_next(
    stream: &mut Option<MempoolStream>,
) -> anyhow::Result<Option<service::RawTransaction>> {
    match stream {
        Some(s) => s.message().await,
        None => std::future::pending().await,
    }
}

/// Lock the shared seed, recovering from a poisoned mutex. The guarded operations (derive/set/
/// lock/clone) are trivial and shouldn't panic, but if one ever did while holding the guard,
/// recovering the inner value keeps a single bad command from wedging every later seed access -
/// and crucially never blocks `walletlock` from zeroizing the seed.
fn seed_guard(seed: &SharedSeed) -> std::sync::MutexGuard<'_, SeedKeeper> {
    seed.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Sleep until the unlock deadline, or forever when there is none. Used as a `select!` arm so an
/// encrypted wallet's seed is zeroized promptly once its `walletpassphrase` timeout elapses.
async fn relock_sleep(until: Option<Instant>) {
    match until {
        Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
        None => std::future::pending::<()>().await,
    }
}

/// Current unix time in seconds (for reporting `unlocked_until`).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Prove (Orchard, plus Sapling outputs if any) and sign the Orchard spends with the account's
/// key, returning the signed PCZT ready to extract+store. This is the **pure-CPU** half of a PCZT
/// send (phase B): it touches no DB, so it can run off the single-writer actor (see
/// `[spend] pipeline_proving`). zecd wallets spend only Orchard notes (no transparent or Sapling
/// spends), so the only spend authorizations required are the Orchard ones. Pair with
/// [`store_pczt`] for phase C.
fn prove_sign_pczt(
    pczt: pczt::Pczt,
    usk: &zcash_keys::keys::UnifiedSpendingKey,
    sapling_prover: &LocalTxProver,
    keys: &ProvingKeyCache,
) -> Result<pczt::Pczt, RpcError> {
    use pczt::roles::prover::Prover;
    use pczt::roles::signer::{Error as SignerError, Signer};

    // Proofs. Every zecd send spends Orchard notes (Orchard proof always required); a Sapling
    // output proof is only needed when a recipient is a Sapling address.
    let prover = Prover::new(pczt);
    let prover = if prover.requires_orchard_proof() {
        prover
            .create_orchard_proof(&keys.orchard_pk)
            .map_err(|e| RpcError::wallet(format!("Orchard proof generation failed: {e:?}")))?
    } else {
        prover
    };
    let prover = if prover.requires_sapling_proofs() {
        prover
            .create_sapling_proofs(sapling_prover, sapling_prover)
            .map_err(|e| RpcError::wallet(format!("Sapling proof generation failed: {e:?}")))?
    } else {
        prover
    };
    let pczt = prover.finish();

    // Spend authorization - sign every Orchard spend. The wallet has a single account, so every
    // spend is ours; `InvalidIndex` marks the end of the spend list, any other error is fatal.
    let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    let mut signer = Signer::new(pczt)
        .map_err(|e| RpcError::wallet(format!("PCZT signer init failed: {e:?}")))?;
    let mut index = 0;
    loop {
        match signer.sign_orchard(index, &ask) {
            // Signed one of our spends, or hit a spend whose authorizing key isn't ours -
            // Orchard bundles pad with dummy spends carrying random keys, so
            // `WrongSpendAuthorizingKey` is expected and skipped (exactly as librustzcash's
            // own signer loop does). A genuinely-unsigned real spend is caught later by
            // `extract_and_store_transaction_from_pczt`, which refuses an incomplete PCZT.
            Ok(())
            | Err(SignerError::OrchardSign(orchard::pczt::SignerError::WrongSpendAuthorizingKey)) => {
                index += 1
            }
            // No more Orchard spends to sign.
            Err(SignerError::InvalidIndex) => break,
            Err(e) => {
                return Err(RpcError::wallet(format!(
                    "Orchard spend signing failed: {e:?}"
                )))
            }
        }
    }
    Ok(signer.finish())
}

/// Finalize + persist a proven, signed PCZT (phase C): records the tx, its spends/change, and
/// marks inputs spent - the same wallet bookkeeping `create_proposed_transactions` does. A DB
/// write, so it runs on the single-writer actor. The cached verifying key avoids regenerating it
/// per send; no Sapling verifying key is needed since zecd never produces Sapling spends. `N` (the
/// note-ref type) is otherwise unconstrained here - it only appears in the error type - so pin it
/// to our `WalletDb`'s note ref, as `error::ProposalError` does for the fused path.
fn store_pczt(
    db: &mut WriteDb,
    pczt: pczt::Pczt,
    keys: &ProvingKeyCache,
) -> Result<TxId, RpcError> {
    extract_and_store_transaction_from_pczt::<_, zcash_client_sqlite::ReceivedNoteId>(
        db,
        pczt,
        None,
        Some(&keys.orchard_vk),
    )
    .map_err(|e| RpcError::wallet(format!("storing transaction failed: {e}")))
}

/// A send's size, for the latency log line. Proving cost scales with `orchard_actions`; a large,
/// note-fragmented wallet inflates `inputs` (and thus actions), which is the headline scaling
/// finding. Summed across the proposal's steps.
#[derive(Clone, Copy, Default)]
struct SendShape {
    /// Orchard notes the send spends (zecd spends only Orchard).
    inputs: usize,
    /// Orchard actions built across all steps (`sum of max(spends, outputs)`).
    orchard_actions: usize,
}

/// Summarize a built proposal's spend/action counts for the send-latency log.
fn proposal_shape<FeeRuleT, NoteRef>(proposal: &Proposal<FeeRuleT, NoteRef>) -> SendShape {
    let mut shape = SendShape::default();
    for step in proposal.steps() {
        let (spends, outputs) = step_orchard_actions(step);
        shape.inputs += spends;
        shape.orchard_actions += spends.max(outputs);
    }
    shape
}

/// Read a just-created transaction's raw bytes back from the wallet DB (for broadcast).
fn read_raw_tx(db: &WriteDb, txid: TxId) -> Result<Vec<u8>, RpcError> {
    let tx = db
        .get_transaction(txid)
        .map_err(RpcError::database_internal)?
        .ok_or_else(|| RpcError::wallet("created transaction not found in wallet"))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;
    Ok(raw)
}

/// Emit the per-send latency profile (the Layer-0 instrumentation): which path proved the send,
/// its shape, and the wall time of each phase. `path` is `inline` / `fused` / `pipelined`. On a
/// large wallet this line is the primary stress-test artifact - it shows whether the minutes land
/// in selection (`select+build`) or proving (`prove`).
#[allow(clippy::too_many_arguments)]
fn log_send_latency(
    name: &str,
    path: &str,
    shape: SendShape,
    build: Duration,
    prove: Duration,
    store: Duration,
    broadcast: Duration,
) {
    info!(
        "[{name}] send complete ({path}): {} inputs, {} orchard actions; \
         select+build {} ms, prove+sign {} ms, store {} ms, broadcast {} ms",
        shape.inputs,
        shape.orchard_actions,
        build.as_millis(),
        prove.as_millis(),
        store.as_millis(),
        broadcast.as_millis(),
    );
}

/// Map a PCZT create/extract error to an `RpcError`, surfacing insufficient-funds conditions as
/// `-6` like [`classify_err`] does for the fused path (so `enrich_insufficient_funds` can add
/// the pending-balance hint). PCZT errors are a different generic instantiation of the same
/// librustzcash `Error`, so classify by message rather than re-matching variants.
fn classify_pczt_err<E: std::fmt::Display>(e: E) -> RpcError {
    let s = e.to_string();
    if s.to_lowercase().contains("insufficient") {
        RpcError::insufficient_funds(s)
    } else {
        RpcError::wallet(s)
    }
}

/// The `FullPrivacy` single-pool rule, factored out for unit testing: a step violates it if it
/// has any transparent component, or if it touches **both** shielded pools (a Sapling↔Orchard
/// turnstile crossing, which reveals the crossed amount on-chain via `valueBalance`).
fn single_pool_violated(transparent: bool, sapling: bool, orchard: bool) -> bool {
    transparent || (sapling && orchard)
}

/// Enforce `[spend] privacy_policy = FullPrivacy` on a built proposal: every step must stay within
/// a single shielded pool (no transparent inputs/outputs/change, no Sapling↔Orchard crossing).
/// `Step::involves` reports whether a step's inputs, payment outputs, *or* change touch a pool, so
/// this mirrors zallet's `enforce_privacy_policy`. Returns `-8` if the policy can't be honoured.
fn enforce_full_privacy<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
) -> Result<(), RpcError> {
    for step in proposal.steps() {
        let transparent = step.involves(PoolType::Transparent);
        let sapling = step.involves(PoolType::SAPLING);
        let orchard = step.involves(PoolType::ORCHARD);
        if single_pool_violated(transparent, sapling, orchard) {
            return Err(RpcError::invalid_parameter(
                "Privacy policy FullPrivacy rejects this send: it would leave a single shielded \
                 pool (a transparent component, or a Sapling<->Orchard crossing that reveals the \
                 transferred amount on-chain). Set [spend] privacy_policy = \
                 \"AllowRevealedRecipients\" to permit this.",
            ));
        }
    }
    Ok(())
}

/// Orchard actions a single proposal step contributes: `max(orchard inputs, orchard outputs)`,
/// since each Orchard action carries one spend and one output (a dummy filling whichever side is
/// short). Mirrors the count Zallet's `orchard_actions` limit checks. `orchard_outputs` counts
/// both payment outputs landing in the Orchard pool and Orchard change notes.
fn step_orchard_actions<NoteRef>(
    step: &zcash_client_backend::proposal::Step<NoteRef>,
) -> (usize, usize) {
    let orchard_spends = step
        .shielded_inputs()
        .iter()
        .flat_map(|inputs| inputs.notes().iter())
        .filter(|note| note.note().protocol() == ShieldedProtocol::Orchard)
        .count();

    let orchard_outputs = step
        .payment_pools()
        .values()
        .filter(|&&pool| pool == PoolType::ORCHARD)
        .count()
        + step
            .balance()
            .proposed_change()
            .iter()
            .filter(|change| change.output_pool() == PoolType::ORCHARD)
            .count();

    (orchard_spends, orchard_outputs)
}

/// Enforce `[spend] orchard_action_limit` on a built proposal: no step may exceed `limit` Orchard
/// actions. `limit == 0` disables the cap. Returns `-8` naming whether inputs or outputs (or both)
/// overflow, like Zallet's error, so an over-large `z_sendmany` is self-diagnosing rather than
/// failing deep in proving. The check sits on the proposal because the input (spend) count is only
/// known once note selection has run.
fn enforce_orchard_action_limit<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    limit: usize,
) -> Result<(), RpcError> {
    if limit == 0 {
        return Ok(());
    }
    for step in proposal.steps() {
        let (orchard_spends, orchard_outputs) = step_orchard_actions(step);
        if let Some((count, kind)) = orchard_action_overflow(orchard_spends, orchard_outputs, limit)
        {
            return Err(RpcError::invalid_parameter(format!(
                "Including {count} Orchard {kind} would exceed the current limit of {limit} \
                 actions, which exists to bound this send's memory and proving cost. Raise \
                 [spend] orchard_action_limit (or set it to 0 to disable the cap) to allow this \
                 transaction."
            )));
        }
    }
    Ok(())
}

/// Decide whether an Orchard-action count overflows `limit` (assumed non-zero), and if so report
/// the offending `(count, kind)` for the error message: blame `inputs` or `outputs` when only one
/// side overflows, else `actions` (the `max`). Returns `None` when within the cap.
fn orchard_action_overflow(
    spends: usize,
    outputs: usize,
    limit: usize,
) -> Option<(usize, &'static str)> {
    if spends.max(outputs) <= limit {
        return None;
    }
    Some(if outputs <= limit {
        (spends, "inputs")
    } else if spends <= limit {
        (outputs, "outputs")
    } else {
        (spends.max(outputs), "actions")
    })
}

/// Classify a librustzcash spend/proposal error into a Bitcoin-Core RPC code. Insufficient
/// funds maps to -6; everything else to the generic wallet error -4. Client-facing messages
/// use `Display` (not `Debug`) so internal note/proposal structure isn't leaked.
fn classify_err(e: crate::error::ProposalError) -> RpcError {
    use zcash_client_backend::data_api::error::Error;
    match &e {
        Error::InsufficientFunds {
            available,
            required,
        } => RpcError::insufficient_funds(format!(
            "Insufficient funds: {} zatoshis spendable, {} required (including fee)",
            u64::from(*available),
            u64::from(*required),
        )),
        // Insufficient-balance conditions can also surface from the change strategy
        // (e.g. `ChangeError::InsufficientFunds`); catch those by message.
        _ => {
            let s = e.to_string();
            if s.to_lowercase().contains("insufficient") {
                RpcError::insufficient_funds(s)
            } else {
                RpcError::wallet(s)
            }
        }
    }
}

/// Append the wallet's pending balance to an insufficient-funds (`-6`) error, so the common
/// rapid-send case (spendable notes exhausted while shielded change awaits confirmations) is
/// self-diagnosing: the caller can tell "retry once confirmations arrive" apart from "fund
/// the wallet". Any other error passes through untouched. Looking up the summary here is
/// safe: a `-6` means a proposal actually ran, which implies the chain tip is set (the
/// `get_wallet_summary` progress-estimator underflow guarded against in `update_status`
/// can't fire), and a failed lookup just leaves the message unenriched.
fn enrich_insufficient_funds(db: &WriteDb, policy: ConfirmationsPolicy, err: RpcError) -> RpcError {
    if err.code != codes::RPC_WALLET_INSUFFICIENT_FUNDS {
        return err;
    }
    let Ok(Some(summary)) = db.get_wallet_summary(policy) else {
        return err;
    };
    let (mut incoming, mut change) = (0u64, 0u64);
    for bal in summary.account_balances().values() {
        incoming += bal
            .orchard_balance()
            .value_pending_spendability()
            .into_u64()
            + bal
                .sapling_balance()
                .value_pending_spendability()
                .into_u64();
        change += bal
            .orchard_balance()
            .change_pending_confirmation()
            .into_u64()
            + bal
                .sapling_balance()
                .change_pending_confirmation()
                .into_u64();
    }
    if incoming == 0 && change == 0 {
        return err;
    }
    RpcError::insufficient_funds(format!(
        "{}; awaiting confirmations: {incoming} zatoshis incoming, {change} zatoshis change \
 - these become spendable as blocks arrive",
        err.message
    ))
}

#[cfg(test)]
mod tests {
    use super::sanitize_upstream_msg;

    /// The launch-time data-directory writability probe: succeeds on a fresh writable dir
    /// (creating it if needed) and fails clearly when the path can't be a writable directory.
    #[test]
    fn ensure_dir_writable_probes_the_data_directory() {
        use super::ensure_dir_writable;
        let dir = tempfile::tempdir().unwrap();

        // A writable directory passes, and the probe file is cleaned up (not left behind).
        let wd = dir.path().join("wallet");
        ensure_dir_writable(&wd).expect("a fresh writable dir is usable");
        assert!(wd.is_dir());
        assert!(
            !wd.join(".zecd-write-test").exists(),
            "the probe file is removed"
        );

        // A path that cannot be a directory (its parent is a regular file) fails - portable
        // across uids, unlike chmod-based read-only tests that root bypasses.
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        assert!(
            ensure_dir_writable(&file.join("sub")).is_err(),
            "a non-directory parent must fail the writability probe"
        );
    }

    /// The enhancement backlog counts only requests zecd can actually service: full-tx
    /// `Enhancement` and `GetStatus`. The transparent-address variant (which zecd has no source
    /// for and skips) must be excluded, or it would pin `pending_enhancements` above zero forever
    /// and a wallet would never report ready.
    #[test]
    fn serviceable_request_classification() {
        use super::is_serviceable_request;
        use zcash_client_backend::data_api::TransactionDataRequest;
        use zcash_protocol::TxId;

        let txid = TxId::from_bytes([7u8; 32]);
        assert!(is_serviceable_request(
            &TransactionDataRequest::Enhancement(txid)
        ));
        assert!(is_serviceable_request(&TransactionDataRequest::GetStatus(
            txid
        )));
    }

    /// FullPrivacy's single-pool rule: violated by any transparent component, or by touching
    /// both shielded pools (a Sapling<->Orchard turnstile crossing). A transaction confined to
    /// one shielded pool is fine.
    #[test]
    fn single_pool_rule() {
        use super::single_pool_violated;
        // Single shielded pool - allowed.
        assert!(!single_pool_violated(false, true, false)); // Sapling only
        assert!(!single_pool_violated(false, false, true)); // Orchard only
                                                            // Cross-pool turnstile - rejected.
        assert!(single_pool_violated(false, true, true));
        // Any transparent component - rejected.
        assert!(single_pool_violated(true, false, true));
        assert!(single_pool_violated(true, true, false));
        assert!(single_pool_violated(true, false, false));
    }

    /// The Orchard-action cap: `max(spends, outputs)` must not exceed the limit; the error blames
    /// whichever side overflows (or `actions` when both do).
    #[test]
    fn orchard_action_overflow_decision() {
        use super::orchard_action_overflow;
        // Within the cap - no overflow regardless of which side is larger.
        assert_eq!(orchard_action_overflow(50, 50, 50), None);
        assert_eq!(orchard_action_overflow(10, 50, 50), None);
        assert_eq!(orchard_action_overflow(0, 0, 50), None);
        // Only outputs overflow → blame outputs.
        assert_eq!(orchard_action_overflow(3, 51, 50), Some((51, "outputs")));
        // Only inputs overflow → blame inputs.
        assert_eq!(orchard_action_overflow(80, 2, 50), Some((80, "inputs")));
        // Both overflow → blame actions (the max).
        assert_eq!(orchard_action_overflow(60, 70, 50), Some((70, "actions")));
        // A tight cap of 1: a single extra output trips it.
        assert_eq!(orchard_action_overflow(1, 2, 1), Some((2, "outputs")));
    }

    /// Resubmitting a tx the node already has must follow Bitcoin Core's idempotent
    /// `sendrawtransaction` contract; these are the reject strings zebra/zcashd actually
    /// emit (the zebra mempool one raced the rebroadcast loop in the regtest e2e).
    #[test]
    fn already_known_rejections_are_classified() {
        use super::{upstream_already_has_tx, AlreadyKnown};

        // zebra via lightwalletd (observed in the funded e2e).
        assert_eq!(
            upstream_already_has_tx("transaction already exists in mempool"),
            AlreadyKnown::InMempool
        );
        // zcashd-style reject reasons.
        assert_eq!(
            upstream_already_has_tx("txn-already-in-mempool"),
            AlreadyKnown::InMempool
        );
        assert_eq!(
            upstream_already_has_tx("txn-already-known"),
            AlreadyKnown::InMempool
        );
        assert_eq!(
            upstream_already_has_tx("transaction already in block chain"),
            AlreadyKnown::InChain
        );
        // Genuine rejections keep surfacing as -26.
        assert_eq!(
            upstream_already_has_tx("tx unpaid action limit exceeded"),
            AlreadyKnown::No
        );
        assert_eq!(
            upstream_already_has_tx("insufficient fee"),
            AlreadyKnown::No
        );
    }

    /// Upstream reject reasons are relayed to RPC clients, but bounded: control characters
    /// stripped, length capped (the upstream is operator-configured, not trusted-honest).
    #[test]
    fn upstream_messages_are_bounded_before_echoing() {
        // Ordinary reject reasons pass through unchanged.
        let real = "tx unpaid action limit exceeded";
        assert_eq!(sanitize_upstream_msg(real), real);
        // Control characters (log/terminal injection) are stripped.
        assert_eq!(sanitize_upstream_msg("a\r\nb\x1b[31mc"), "ab[31mc");
        // Oversized messages are truncated with an ellipsis marker.
        let long = "x".repeat(500);
        let bounded = sanitize_upstream_msg(&long);
        assert_eq!(bounded.chars().count(), 201);
        assert!(bounded.ends_with('…'));
        // Exactly at the cap: no marker.
        let exact = "y".repeat(200);
        assert_eq!(sanitize_upstream_msg(&exact), exact);
    }

    /// The wrong-chain guard enforces only the mainnet/non-mainnet boundary. The regtest
    /// case is the load-bearing one: zebra-backed lightwalletd reports `"test"` on regtest
    /// (zebra's `bip70_network_name` only distinguishes mainnet), and treating that as a
    /// mismatch bricked the regtest e2e - the actor rejected its only server on every
    /// connect and never synced.
    #[test]
    fn chain_name_guard_checks_only_the_mainnet_boundary() {
        use super::chain_name_is_main;

        assert_eq!(chain_name_is_main("main"), Some(true));
        assert_eq!(chain_name_is_main("test"), Some(false));
        assert_eq!(chain_name_is_main("regtest"), Some(false));
        // Unrecognized names skip the check (warn only).
        assert_eq!(chain_name_is_main(""), None);
        assert_eq!(chain_name_is_main("Main"), None);

        // What verify_server_network derives from these classifications:
        let is_main = |net: super::ZNetwork| matches!(net, super::ZNetwork::Main);
        // zebra regtest reports "test"; a regtest wallet must accept it.
        assert_eq!(
            chain_name_is_main("test"),
            Some(is_main(crate::network::regtest()))
        );
        // The boundary that matters: a mainnet wallet rejects test chains and vice versa.
        assert_ne!(
            chain_name_is_main("test"),
            Some(is_main(super::ZNetwork::Main))
        );
        assert_ne!(
            chain_name_is_main("main"),
            Some(is_main(super::ZNetwork::Test))
        );
    }

    /// `enrich_insufficient_funds` must touch *only* a -6 whose wallet actually has value
    /// awaiting confirmations: other codes and a no-pending -6 pass through byte-identical
    /// (clients match on these messages; never churn them gratuitously).
    #[test]
    fn insufficient_funds_enrichment_leaves_other_errors_alone() {
        use super::{codes, BlockHeight, RpcError};
        use zcash_client_backend::data_api::chain::ChainState;
        use zcash_client_backend::data_api::{AccountBirthday, WalletWrite};
        use zcash_primitives::block::BlockHash;

        let net = crate::network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let mut db = crate::wallet::open::init_dbs(net, dir.path()).expect("init dbs");
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
            None,
        );
        db.create_account(
            "t",
            &secrecy::SecretVec::new(vec![1u8; 64]),
            &birthday,
            None,
        )
        .expect("create account");
        // The tip must be set before `get_wallet_summary` (progress-estimator underflow
        // gotcha); the production call site inherits this from the completed proposal.
        db.update_chain_tip(BlockHeight::from_u32(5))
            .expect("set tip");

        let other = RpcError::wallet("some other failure");
        assert_eq!(
            super::enrich_insufficient_funds(&db, Default::default(), other.clone()).message,
            other.message
        );

        let bare = RpcError::insufficient_funds("Insufficient funds: 0 zatoshis spendable");
        let out = super::enrich_insufficient_funds(&db, Default::default(), bare.clone());
        assert_eq!(out.code, codes::RPC_WALLET_INSUFFICIENT_FUNDS);
        assert_eq!(
            out.message, bare.message,
            "no pending balance, so no enrichment"
        );
    }

    /// `sendrawtransaction`'s upstream verdict must follow Bitcoin Core's exact codes:
    /// accepted/already-in-mempool succeed, already-mined is -27, anything else is -26 with a
    /// bounded reason. This locks the RPC-code mapping that `do_broadcast` defers to.
    #[test]
    fn broadcast_outcome_maps_to_bitcoind_codes() {
        use super::{classify_broadcast_outcome, codes};
        use crate::chain::BroadcastOutcome;

        let outcome = |code, msg: &str| BroadcastOutcome {
            error_code: code,
            error_message: msg.to_string(),
        };

        // Accepted (error_code 0) is success.
        assert!(classify_broadcast_outcome(&outcome(0, "")).is_ok());

        // Already in the mempool is idempotent success (Core's sendrawtransaction contract).
        assert!(
            classify_broadcast_outcome(&outcome(-25, "transaction already exists in mempool"))
                .is_ok()
        );

        // Already mined -> -27 with Bitcoin Core's exact default message.
        let e = classify_broadcast_outcome(&outcome(-25, "transaction already in block chain"))
            .unwrap_err();
        assert_eq!(e.code, codes::RPC_VERIFY_ALREADY_IN_UTXO_SET);
        assert_eq!(e.message, "Transaction outputs already in utxo set");

        // A genuine rejection -> -26, surfacing the upstream code and reason.
        let e = classify_broadcast_outcome(&outcome(64, "tx unpaid action limit exceeded"))
            .unwrap_err();
        assert_eq!(e.code, codes::RPC_VERIFY_REJECTED);
        assert!(e.message.contains("code 64"), "{}", e.message);
        assert!(e.message.contains("unpaid action limit"), "{}", e.message);

        // The upstream reason is sanitized (no control chars) before it reaches the client.
        let e = classify_broadcast_outcome(&outcome(1, "bad\r\n\x1b[31mtx")).unwrap_err();
        assert_eq!(e.code, codes::RPC_VERIFY_REJECTED);
        assert!(
            !e.message.contains('\n') && !e.message.contains('\u{1b}'),
            "control chars leaked: {:?}",
            e.message
        );
    }
}
