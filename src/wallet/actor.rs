//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, decrypt_and_store_transaction,
    input_selection::GreedyInputSelector, propose_transfer, ConfirmationsPolicy, SpendingKeys,
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
use crate::pools::PoolSet;
use crate::sync::engine;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::read;
use crate::wallet::{
    labels, make_handle, store, ConnState, RawTx, SyncStatus, WalletCommand, WalletHandle,
};

/// Note-management defaults for change splitting (match zcash-devtool's send defaults).
const TARGET_NOTE_COUNT: usize = 4;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000; // 0.1 ZEC

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
    prover: LocalTxProver,
    seed: SeedKeeper,
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

    // The data directory must be writable: zecd creates/updates data.sqlite, blocks/ and
    // labels.sqlite there. Probe it up front so a read-only mount fails with a clear error now,
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

    // The local prover bundles Sapling parameters; build it once (off the async threads).
    let prover = tokio::task::spawn_blocking(LocalTxProver::bundled)
        .await
        .map_err(|e| anyhow!("failed to build prover: {e}"))?;

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
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
        account_id,
        account_index,
        pending_bootstrap,
        db_data,
        db_cache,
        client: None,
        connected_logged: false,
        prover,
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
            cmd_tx,
            status_rx,
        ),
        task,
    ))
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
            "data directory {} is not writable (zecd must create and update data.sqlite, \
             blocks/, and labels.sqlite there)",
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
                match self.sync_step().await {
                    Ok(worked) => {
                        more_work = worked;
                        if !worked {
                            // Caught up: give any unmined wallet txs another shot at the mempool,
                            // pull the full data (memos, …) for transactions seen only as compact
                            // blocks, and (re)subscribe to incoming mempool txs for 0-conf visibility.
                            self.maybe_rebroadcast().await;
                            self.enhance_transactions().await;
                            self.ensure_mempool_stream().await;
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
                    Relock,
                    Tick,
                    Mempool(anyhow::Result<Option<service::RawTransaction>>),
                }
                let event = {
                    let mut mempool = self.mempool.take();
                    let event = tokio::select! {
                        res = self.shutdown.changed() => IdleEvent::Shutdown(res),
                        maybe_cmd = self.cmd_rx.recv() => IdleEvent::Cmd(maybe_cmd),
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

    /// Service the wallet's pending transaction-data requests - the "enhancement" step.
    /// `scan_cached_blocks` records these (`WalletRead::transaction_data_requests`) while
    /// scanning compact blocks, which carry no memos and no full transparent data: for each
    /// request, fetch the full transaction from the upstream and either decrypt+store it
    /// (which fills in `v_tx_outputs.memo` on received shielded outputs) or record its chain
    /// status. Called only when caught up to the tip.
    ///
    /// Without this, a memo on a transaction the wallet only ever saw as a compact block -
    /// every receive picked up during initial sync or a `--restore`, and any live receive the
    /// mempool stream missed - never appears in `gettransaction`/`listtransactions`, because
    /// the compact-block scan records the tx as mined with a NULL memo and nothing ever
    /// backfills it. (A receive the mempool stream *does* catch is already enhanced: that path
    /// stores the full tx via `decrypt_and_store_transaction`.)
    ///
    /// Mirrors zcash-devtool's `enhance` command and zkv's `enhance`. Best-effort: a transport
    /// failure drops the client (so the next loop reconnects/fails over) and aborts the pass;
    /// the still-pending requests are retried on the next caught-up pass. librustzcash removes
    /// each request once it is satisfied, so a clean pass converges and stops re-fetching.
    async fn enhance_transactions(&mut self) {
        let Some(tip) = self.tip_height else { return };
        if self.client.is_none() {
            return;
        }
        let chain_tip = BlockHeight::from_u32(tip);
        // Requests are removed from the wallet as they're satisfied; track those handled in
        // this pass so a request the upstream can't satisfy (left in place) can't spin the
        // re-query loop. Mirrors zcash-devtool/zkv's `satisfied` set.
        let mut satisfied = std::collections::BTreeSet::new();
        loop {
            let requests = match self.db_data.transaction_data_requests() {
                Ok(r) => r,
                Err(e) => {
                    warn!("[{}] reading transaction data requests: {e}", self.name);
                    return;
                }
            };
            let mut any_new = false;
            for req in requests {
                if satisfied.contains(&req) {
                    continue;
                }
                any_new = true;
                if let Err(e) = self.service_data_request(&req, chain_tip).await {
                    // A transport failure has already dropped the client (a DB-write error just
                    // aborts the pass); either way, stop here and retry the remaining requests
                    // on the next caught-up pass rather than spinning on a persistent failure.
                    tracing::debug!("[{}] transaction enhancement aborted: {e}", self.name);
                    return;
                }
                satisfied.insert(req);
            }
            if !any_new {
                break;
            }
        }
    }

    /// Handle one [`TransactionDataRequest`] for [`enhance_transactions`]. Returns `Err` only
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
                // If the tx turned out to be ours (decrypt stored a row), record when we
                // first saw it: `gettransaction`/`listtransactions` report it as
                // `time`/`timereceived` while the tx is unmined, like Bitcoin Core's
                // `nTimeReceived`. Best-effort, idempotent (INSERT OR IGNORE).
                let txid_hex = txid.to_string();
                if super::read::tx_exists(&self.wallet_dir, &txid_hex) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if let Err(e) =
                        super::labels::record_first_seen(&self.wallet_dir, &txid_hex, now)
                    {
                        tracing::debug!("[{}] failed to record first-seen time: {e}", self.name);
                    }
                }
            }
            Err(e) => warn!("[{}] failed to store mempool tx {txid}: {e}", self.name),
        }
    }

    async fn refresh_tip(&mut self) -> anyhow::Result<()> {
        let chain_tip = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| anyhow!("not connected"))?;
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.latest_block())
                .await
                .map_err(|_| anyhow!("latest_block timed out after {UNARY_RPC_TIMEOUT:?}"))??
        };
        let tip = BlockHeight::try_from(chain_tip.height)
            .map_err(|_| anyhow!("chain tip height out of range"))?;
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
        if self.account_id.is_some() {
            self.db_data.update_chain_tip(tip)?;
        }
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
        if chain_tip.hash.len() == 32 {
            let mut h = chain_tip.hash.clone();
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
        let Some(seed) = self.seed.clone_seed() else {
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

        let conn_state = if self.client.is_none() {
            ConnState::Down
        } else if scanning {
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
            WalletCommand::GetNewAddress {
                label,
                receivers,
                reply,
            } => {
                let res = self.get_new_address(label, receivers);
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
                let res = self.do_send(request, confirmations, privacy).await;
                let _ = reply.send(res);
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
            self.seed.lock();
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

    fn get_new_address(
        &mut self,
        label: Option<String>,
        receivers: Option<PoolSet>,
    ) -> Result<String, RpcError> {
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
        if let Some(label) = label {
            if let Err(e) = labels::set_label(&self.wallet_dir, &encoded, &label) {
                warn!("[{}] failed to store label: {e}", self.name);
            }
        }
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
        let account_id = self.require_account()?;
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        let usk = self.seed.derive_usk(self.network, account_index)?;

        // Proposal building + proving is CPU-heavy (Sapling/Orchard proofs take seconds).
        // Run it under `block_in_place` so it doesn't stall the async runtime, and so the
        // single send doesn't block the actor thread from being cooperatively yielded.
        let net = self.network;
        // A per-call `minconf` (z_sendmany) overrides the wallet-wide policy for this send's
        // note selection; the synchronous sends pass `None` and use the configured policy.
        let policy = confirmations.unwrap_or(self.confirmations_policy);
        let orchard_action_limit = self.orchard_action_limit;
        let change_pool = self.enabled_pools.change_pool();
        let prover = &self.prover;
        let db = &mut self.db_data;
        let (txid, raw): (TxId, Vec<u8>) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let change_strategy = MultiOutputChangeStrategy::new(
                    StandardFeeRule::Zip317,
                    None,
                    // Change goes to the strongest enabled pool (Orchard if enabled, else the
                    // first enabled pool); inputs are still selected from any pool by the
                    // greedy selector.
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

                // FullPrivacy: reject before the (expensive) proving step if the proposal would
                // leave a single shielded pool - i.e. involve a transparent component or cross
                // the Sapling↔Orchard turnstile (which reveals the crossed amount on-chain).
                // The input pool is only known now that the proposal is built, so this is where
                // the no-cross-pool half of the policy is enforced (the no-transparent-recipient
                // half is a cheap pre-check in `build_payment`).
                if privacy == SendPrivacy::FullPrivacy {
                    enforce_full_privacy(&proposal)?;
                }

                // Cap the Orchard actions before the (expensive) proving step, so a send with
                // too many recipients fails fast with a clear `-8` instead of exhausting memory
                // or surfacing a deep librustzcash error (mirrors Zallet's `orchard_actions`).
                enforce_orchard_action_limit(&proposal, orchard_action_limit)?;

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

                let tx = db
                    .get_transaction(txid)
                    .map_err(RpcError::database_internal)?
                    .ok_or_else(|| RpcError::wallet("created transaction not found in wallet"))?;
                let mut raw_tx = Vec::new();
                tx.write(&mut raw_tx)
                    .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;
                Ok((txid, raw_tx))
            })?;

        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        Ok(txid)
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
        self.seed.set(seed);
        // Re-running walletpassphrase overwrites the deadline (resets the timer). A timeout of 0
        // relocks ~immediately, which `relock_if_expired` then enforces.
        self.unlock_until = Some(Instant::now() + Duration::from_secs(timeout_secs.max(0) as u64));
        self.relock_if_expired();
        // First unlock of an encrypted wallet on an empty data directory: now that the seed is
        // available, rebuild the account from keys.toml right away (best-effort; if the upstream
        // isn't connected yet the regular sync loop retries). Skipped if the timeout was 0 (the
        // seed was just relocked) or no bootstrap is pending.
        if self.pending_bootstrap.is_some() && self.seed.is_unlocked() {
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
        self.seed.lock();
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

/// Classify a librustzcash spend/proposal error into a Bitcoin-Core RPC code. Insufficient
/// funds maps to -6; everything else to the generic wallet error -4. Client-facing messages
/// use `Display` (not `Debug`) so internal note/proposal structure isn't leaked.
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
