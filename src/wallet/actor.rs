//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use secrecy::ExposeSecret;
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, decrypt_and_store_transaction,
    input_selection::GreedyInputSelector, propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{
    Account, AccountPurpose, AccountSource, WalletRead, WalletWrite,
};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
};
use zcash_client_backend::proto::service;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_sqlite::{AccountUuid, FsBlockDb};
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::transaction::Transaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedProtocol, TxId};
use zip321::TransactionRequest;

use crate::backoff::Backoff;
use crate::chain::{AnySource, ChainSource, MempoolStream};
use crate::error::{codes, RpcError};
use crate::lightwalletd::Server;
use crate::network::ZNetwork;
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

/// Upper bound on the per-attempt dial timeout used when re-probing higher-priority servers,
/// so a black-holed primary can't stall the command loop for the full `connect_timeout` on
/// each `primary_recheck`. A recovered primary connects near-instantly; a dead one fails fast.
const REPROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Deadlines for RPCs issued on an already-connected channel. The dial timeout covers only
/// the TCP/TLS connect, so a peer that hangs *after* accepting would otherwise stall the
/// actor's command loop indefinitely (HTTP/2 keepalive on the channel is the systemic
/// backstop; these make the critical paths deterministic and snappier).
///
/// The post-connect health check may include the one-time subtree-root stream (hundreds of
/// roots on mainnet), so it gets a generous budget...
const PREPARE_TIMEOUT: Duration = Duration::from_secs(60);
/// ...while a primary re-probe runs from the idle loop with a healthy fallback active, so it
/// must stay tight (roots are already synced by then; this is a cheap liveness ping).
const REPROBE_PREPARE_TIMEOUT: Duration = Duration::from_secs(10);
/// Unary calls (broadcast, tip refresh, tx fetch) on the live channel.
const UNARY_RPC_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Retry state for a KMS wallet whose startup unlock failed: exponential backoff between
/// cloud Decrypt attempts, checked opportunistically as the actor loop turns over.
struct KmsUnlockRetry {
    backoff: Backoff,
    retry_at: Instant,
}

impl KmsUnlockRetry {
    fn new() -> Self {
        let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(300));
        // Full jitter can return ~0; floor the wait so a hard-down KMS isn't hammered.
        let delay = backoff.next_delay().max(Duration::from_secs(2));
        KmsUnlockRetry {
            backoff,
            retry_at: Instant::now() + delay,
        }
    }

    fn reschedule(&mut self) {
        let delay = self.backoff.next_delay().max(Duration::from_secs(2));
        self.retry_at = Instant::now() + delay;
    }
}

/// Parameters needed to launch a wallet actor.
pub struct ActorConfig {
    pub name: String,
    pub network: ZNetwork,
    pub wallet_dir: PathBuf,
    /// Ordered upstream endpoints (lightwalletd or zebra; non-empty); tried in order,
    /// preferring the first.
    pub servers: Vec<Server>,
    pub sync_interval: Duration,
    /// Minimum spacing between unmined-tx rebroadcast passes.
    pub rebroadcast_interval: Duration,
    /// Per-attempt dial timeout.
    pub connect_timeout: Duration,
    /// Reconnect backoff base/max delays.
    pub reconnect_base: Duration,
    pub reconnect_max: Duration,
    /// While on a fallback, how often to re-probe higher-priority servers.
    pub primary_recheck: Duration,
    pub age_identity: Option<PathBuf>,
    pub auto_unlock: bool,
    /// `[keystore] endpoint` override for cloud-KMS unlock calls (emulators/VPC endpoints).
    /// The provider and key come from the wallet's own `keys.toml`.
    pub keystore_endpoint: Option<String>,
    /// The wallet-wide confirmations policy (`[spend]` config; ZIP-315 3/10 by default),
    /// anchoring balances, spend proposals, and the `-6` enrichment.
    pub confirmations_policy: ConfirmationsPolicy,
    /// Flips to `true` on Ctrl-C/`stop`; the actor exits its loop (between sync batches)
    /// so the `WalletDb` is dropped cleanly before the process ends.
    pub shutdown: watch::Receiver<bool>,
}

struct WalletActor {
    name: String,
    network: ZNetwork,
    wallet_dir: PathBuf,
    /// Ordered upstream endpoints (non-empty); `active` indexes the connected one.
    servers: Vec<Server>,
    active: usize,
    connect_timeout: Duration,
    backoff: Backoff,
    /// When the next reconnect attempt is allowed (a backoff deadline, not a fixed tick), so
    /// commands interrupting the idle wait don't advance the backoff.
    reconnect_at: Instant,
    primary_recheck: Duration,
    last_primary_probe: Instant,
    sync_interval: Duration,
    rebroadcast_interval: Duration,
    age_identity: Option<PathBuf>,
    confirmations_policy: ConfirmationsPolicy,
    account_id: AccountUuid,
    account_index: Option<zip32::AccountId>,
    db_data: WriteDb,
    db_cache: FsBlockDb,
    client: Option<AnySource>,
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
    /// Whether the wallet is passphrase-encrypted (read from `keys.toml` at spawn). Gates the
    /// Bitcoin-Core-style `walletpassphrase`/`walletlock`/`encryptwallet` behavior.
    encrypted: bool,
    /// Whether the wallet's age identity is cloud-KMS-wrapped (`encryption = "kms"`). Such a
    /// wallet auto-unlocks at startup like the identity model ("unencrypted" to the RPCs);
    /// `encryptwallet` migrates it onto a passphrase.
    kms_wallet: bool,
    /// `[keystore] endpoint` override for KMS unlock calls.
    keystore_endpoint: Option<String>,
    /// `Some` while a KMS wallet's startup unlock is failing (e.g. a KMS/IAM outage at
    /// boot): the actor keeps retrying with backoff so a transient outage doesn't require a
    /// human restart. Cleared on success, `encryptwallet`, or a non-retryable condition.
    kms_unlock_retry: Option<KmsUnlockRetry>,
    /// Whether the wallet is watch-only (its account is an imported UFVK with no spending
    /// material). Spend and encryption commands refuse with Bitcoin Core's -4.
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
    if cfg.servers.is_empty() {
        return Err(anyhow!(
            "no upstream servers configured for wallet '{}'",
            cfg.name
        ));
    }
    if !store::WalletStore::exists(&cfg.wallet_dir) {
        return Err(anyhow!(
            "wallet '{}' is not initialized ({} missing); run `zecd init --wallet {}`",
            cfg.name,
            cfg.wallet_dir.join("keys.toml").display(),
            cfg.name
        ));
    }

    let db_data = open::init_dbs(cfg.network, &cfg.wallet_dir)?;
    let db_cache = open::open_fsblockdb(&cfg.wallet_dir)?;
    let (account_id, account_index, watch_only) = select_account(&db_data)?;

    // Determine the wallet's encryption mode, and for unencrypted wallets optionally decrypt
    // the seed up-front for unattended sending. An encrypted wallet has no passphrase at rest,
    // so it cannot auto-unlock - it starts locked and requires `walletpassphrase` (matching
    // Bitcoin Core's encrypted-wallet behavior). A cloud-KMS wallet auto-unlocks via one
    // IAM-gated KMS Decrypt; a failure there (KMS/IAM outage at boot) is retried with
    // backoff by the actor loop rather than requiring a human restart. A watch-only wallet
    // has no seed anywhere, so the whole unlock machinery is moot for it.
    let st = store::WalletStore::read(&cfg.wallet_dir)?;
    let encrypted = st.is_encrypted();
    let kms_wallet = st.kms().is_some();
    let mut seed = SeedKeeper::locked();
    let mut kms_unlock_retry = None;
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
    } else if kms_wallet {
        if cfg.auto_unlock {
            match keys::decrypt_seed_with_keystore(&st, cfg.keystore_endpoint.as_deref()).await {
                Ok(Some(s)) => {
                    seed.set(s);
                    info!(
                        "[{}] seed unlocked via {} for unattended sending",
                        cfg.name,
                        st.kms().expect("kms wallet").provider.name()
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        "[{}] KMS unlock failed at startup: {e:#}; sends will fail (-13) until it succeeds - retrying with backoff",
                        cfg.name
                    );
                    kms_unlock_retry = Some(KmsUnlockRetry::new());
                }
            }
        } else {
            // Mirrors the identity-model dead end below: nothing can unlock a KMS wallet
            // at runtime (walletpassphrase is -15 on it), so warn loudly.
            warn!(
                "[{}] auto_unlock=false on a KMS-wrapped wallet: sends will fail (-13) and \
                 walletpassphrase cannot unlock it (-15). Enable auto_unlock, or migrate to a \
                 passphrase with encryptwallet.",
                cfg.name
            );
        }
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
             walletpassphrase cannot unlock it (-15). Enable auto_unlock, or set a real \
             passphrase with encryptwallet (then restart unlocks via walletpassphrase).",
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
        unlocked_until: encrypted.then_some(0),
        ..SyncStatus::default()
    });

    let actor = WalletActor {
        name: cfg.name.clone(),
        network: cfg.network,
        wallet_dir: cfg.wallet_dir.clone(),
        servers: cfg.servers,
        active: 0,
        connect_timeout: cfg.connect_timeout,
        backoff: Backoff::new(cfg.reconnect_base, cfg.reconnect_max),
        reconnect_at: Instant::now(),
        primary_recheck: cfg.primary_recheck,
        last_primary_probe: Instant::now(),
        sync_interval: cfg.sync_interval,
        rebroadcast_interval: cfg.rebroadcast_interval,
        age_identity: cfg.age_identity,
        confirmations_policy: cfg.confirmations_policy,
        account_id,
        account_index,
        db_data,
        db_cache,
        client: None,
        prover,
        seed,
        status_tx,
        cmd_rx,
        tip_height: None,
        tip_hash: None,
        mempool: None,
        last_rebroadcast: None,
        subtree_roots_synced: false,
        encrypted,
        kms_wallet,
        keystore_endpoint: cfg.keystore_endpoint,
        kms_unlock_retry,
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
            cmd_tx,
            status_rx,
        ),
        task,
    ))
}

/// The actor's view of the wallet's (single) account: its id, the ZIP-32 index spending keys
/// derive at (`None` when no spending is possible), and whether the account is watch-only
/// (imported UFVK - `init --ufvk`).
fn select_account(db: &WriteDb) -> anyhow::Result<(AccountUuid, Option<zip32::AccountId>, bool)> {
    let ids = db.get_account_ids()?;
    let id = *ids
        .first()
        .ok_or_else(|| anyhow!("wallet has no accounts; run `zecd init` first"))?;
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
    Ok((id, index, watch_only))
}

/// Bitcoin Core's exact refusal for spend/key operations on a wallet without private keys
/// (`-4`, wallet.cpp); zecd's watch-only (UFVK) wallets surface it for the same calls.
fn private_keys_disabled() -> RpcError {
    RpcError::wallet("Error: Private keys are disabled for this wallet")
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
            // A KMS wallet whose startup unlock failed retries here (cheap deadline check).
            self.maybe_retry_kms_unlock().await;
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
                            // and (re)subscribe to incoming mempool txs for 0-conf visibility.
                            self.maybe_rebroadcast().await;
                            self.ensure_mempool_stream().await;
                        }
                    }
                    Err(e) => {
                        warn!("[{}] sync error: {e}", self.name);
                        self.client = None;
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
                        } else {
                            // Connected, possibly to a fallback - try to move back to the primary.
                            self.reprobe_primary().await;
                        }
                        if self.client.is_some() {
                            match self.refresh_tip().await {
                                Ok(()) => more_work = true,
                                Err(e) => {
                                    warn!("[{}] tip refresh failed: {e}", self.name);
                                    self.client = None;
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
                                warn!("[{}] tip refresh failed: {e}", self.name);
                                self.client = None;
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

    /// Connect to an upstream, always preferring the primary: try the configured endpoints in
    /// order from the top and use the first that connects (and passes the subtree-root sync). On
    /// success, store the client, record the active server, and reset the reconnect backoff. On
    /// total failure, leave `self.client` as `None` and return the last error.
    async fn connect(&mut self) -> anyhow::Result<()> {
        // Any open mempool stream belongs to the channel being replaced; drop it so it can't
        // pin the old connection alive. It is reopened on the next caught-up sync pass.
        self.mempool = None;
        let n = self.servers.len();
        let mut last_err = None;
        for idx in 0..n {
            let describe = self.servers[idx].describe();
            info!("[{}] connecting to {}", self.name, describe);
            match self.servers[idx]
                .connect_timeout(self.connect_timeout)
                .await
            {
                Ok(client) => {
                    self.client = Some(client);
                    let client = self.client.as_mut().expect("just set");
                    // A reachable-but-unhealthy upstream can still fail here; treat that as this
                    // server failing and fall through to the next candidate.
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
                        last_err = Some(e);
                        continue;
                    }
                    if idx != self.active {
                        warn!(
                            "[{}] now using {} (was {})",
                            self.name,
                            describe,
                            self.servers[self.active].describe()
                        );
                        self.active = idx;
                    }
                    self.backoff.reset();
                    self.last_primary_probe = Instant::now();
                    // NB: do not call `update_status()` here - `get_wallet_summary`'s progress
                    // estimator underflows if invoked before the chain tip is set (see `refresh_tip`).
                    return Ok(());
                }
                Err(e) => {
                    warn!("[{}] connect to {} failed: {e}", self.name, describe);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no lightwalletd servers available")))
    }

    /// While connected to a fallback, periodically try to move back to a higher-priority server
    /// (prefer-primary). No-op when already on the primary, disconnected, or probed too recently.
    /// On success, swaps in the better client and resets backoff.
    async fn reprobe_primary(&mut self) {
        if self.active == 0
            || self.client.is_none()
            || self.last_primary_probe.elapsed() < self.primary_recheck
        {
            return;
        }
        self.last_primary_probe = Instant::now();
        // Cap the probe dial so a black-holed primary can't stall command processing.
        let probe_timeout = self.connect_timeout.min(REPROBE_CONNECT_TIMEOUT);
        for idx in 0..self.active {
            let describe = self.servers[idx].describe();
            let Ok(mut client) = self.servers[idx].connect_timeout(probe_timeout).await else {
                continue;
            };
            // Health check: full subtree-root sync only if not yet done this process, else a
            // cheap `get_latest_block` - so a recovered primary isn't re-streamed all its roots
            // on every recheck (default 60s while on a fallback).
            if let Err(e) = prepare_client(
                &mut client,
                &mut self.db_data,
                self.network,
                &mut self.subtree_roots_synced,
                REPROBE_PREPARE_TIMEOUT,
            )
            .await
            {
                warn!(
                    "[{}] primary re-probe {} not healthy: {e}",
                    self.name, describe
                );
                continue;
            }
            info!(
                "[{}] preferred upstream {} recovered; switching back from {}",
                self.name,
                describe,
                self.servers[self.active].describe()
            );
            self.client = Some(client);
            self.mempool = None; // belonged to the fallback's channel; reopened on next pass
            self.active = idx;
            self.backoff.reset();
            self.update_status();
            return;
        }
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
        self.db_data.update_chain_tip(tip)?;
        self.tip_height = Some(u32::from(tip));
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
        let worked = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| anyhow!("not connected"))?;
            engine::sync_one_batch(
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
            server: Some(self.servers[self.active].describe()),
            conn_state,
            chain_tip: self.tip_height,
            fully_scanned,
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
                    warn!("[{}] rebroadcast transport error: {e}", self.name);
                    self.client = None;
                    self.update_status();
                    return;
                }
            }
        }
    }

    /// Returns `true` if the actor should stop.
    async fn handle_command(&mut self, cmd: WalletCommand) -> bool {
        match cmd {
            WalletCommand::GetNewAddress { label, reply } => {
                let res = self.get_new_address(label);
                let _ = reply.send(res);
            }
            WalletCommand::Send {
                request,
                confirmations,
                reply,
            } => {
                let res = self.do_send(request, confirmations).await;
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
                let res = self.do_unlock(passphrase, timeout_secs);
                let _ = reply.send(res);
            }
            WalletCommand::Lock { reply } => {
                let res = self.do_lock();
                let _ = reply.send(res);
            }
            WalletCommand::EncryptWallet { passphrase, reply } => {
                let res = self.do_encrypt_wallet(passphrase).await;
                let _ = reply.send(res);
            }
            WalletCommand::ChangePassphrase { old, new, reply } => {
                let res = self.do_change_passphrase(old, new);
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

    /// Retry a KMS wallet's failed startup unlock once its backoff deadline passes, so a
    /// transient KMS/IAM outage at boot heals without a restart. No-op (one `Option` check)
    /// unless a retry is pending and due.
    async fn maybe_retry_kms_unlock(&mut self) {
        let due = self
            .kms_unlock_retry
            .as_ref()
            .is_some_and(|r| Instant::now() >= r.retry_at);
        if !due {
            return;
        }
        let result = match store::WalletStore::read(&self.wallet_dir) {
            Ok(st) => {
                keys::decrypt_seed_with_keystore(&st, self.keystore_endpoint.as_deref()).await
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(Some(seed)) => {
                self.seed.set(seed);
                self.kms_unlock_retry = None;
                info!(
                    "[{}] KMS unlock succeeded; seed unlocked for sending",
                    self.name
                );
                self.update_status();
            }
            Ok(None) => {
                // No stored mnemonic - retrying can't help.
                warn!(
                    "[{}] KMS wallet has no stored mnemonic; giving up unlock",
                    self.name
                );
                self.kms_unlock_retry = None;
            }
            Err(e) => {
                let retry = self.kms_unlock_retry.as_mut().expect("checked due above");
                retry.reschedule();
                warn!(
                    "[{}] KMS unlock retry failed: {e:#}; next attempt in ~{:?}",
                    self.name,
                    retry.retry_at.saturating_duration_since(Instant::now())
                );
            }
        }
    }

    fn get_new_address(&mut self, label: Option<String>) -> Result<String, RpcError> {
        let (ua, _) = self
            .db_data
            .get_next_available_address(self.account_id, UnifiedAddressRequest::ORCHARD)
            .map_err(|e| RpcError::wallet(format!("address generation failed: {e}")))?
            .ok_or_else(|| RpcError::wallet("no address available for account"))?;
        let encoded = ua.encode(&self.network);
        if let Some(label) = label {
            if let Err(e) = labels::set_label(&self.wallet_dir, &encoded, &label) {
                warn!("[{}] failed to store label: {e}", self.name);
            }
        }
        Ok(encoded)
    }

    async fn do_send(
        &mut self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
    ) -> Result<TxId, RpcError> {
        // Hard backstop: if an encrypted wallet's unlock has expired but proactive relock
        // hasn't fired yet (e.g. a long sync batch was in progress), lock now so the spend
        // can't slip through past its timeout. `derive_usk` then returns -13 as expected.
        self.relock_if_expired();
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        let usk = self.seed.derive_usk(self.network, account_index)?;

        // Proposal building + proving is CPU-heavy (Sapling/Orchard proofs take seconds).
        // Run it under `block_in_place` so it doesn't stall the async runtime, and so the
        // single send doesn't block the actor thread from being cooperatively yielded.
        let net = self.network;
        let account_id = self.account_id;
        // A per-call `minconf` (z_sendmany) overrides the wallet-wide policy for this send's
        // note selection; the synchronous sends pass `None` and use the configured policy.
        let policy = confirmations.unwrap_or(self.confirmations_policy);
        let prover = &self.prover;
        let db = &mut self.db_data;
        let (txid, raw): (TxId, Vec<u8>) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let change_strategy = MultiOutputChangeStrategy::new(
                    StandardFeeRule::Zip317,
                    None,
                    ShieldedProtocol::Orchard,
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
                self.client = None;
                self.update_status();
                warn!(
                    "[{}] broadcast of {txid} failed in transport ({e}); it will be re-broadcast",
                    self.name
                );
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
                self.client = None;
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
                self.client = None;
                self.update_status();
                return Err(RpcError::misc(format!("transaction broadcast failed: {e}")));
            }
        };
        if !outcome.is_accepted() {
            // Bitcoin Core's sendrawtransaction is idempotent: a tx the node already has in
            // its mempool returns the txid as success (zecd's own rebroadcast loop can race
            // a manual resubmission of a committed send); one already mined is -27.
            match upstream_already_has_tx(&outcome.error_message) {
                AlreadyKnown::InMempool => {
                    info!(
                        "[{}] upstream already has tx in mempool; sendrawtransaction succeeds",
                        self.name
                    );
                    return Ok(());
                }
                AlreadyKnown::InChain => {
                    // Bitcoin Core: TransactionError::ALREADY_IN_UTXO_SET →
                    // RPC_VERIFY_ALREADY_IN_UTXO_SET with this exact default message
                    // (common/messages.cpp TransactionErrorString).
                    return Err(RpcError::new(
                        codes::RPC_VERIFY_ALREADY_IN_UTXO_SET,
                        "Transaction outputs already in utxo set",
                    ));
                }
                AlreadyKnown::No => {}
            }
            let reason = sanitize_upstream_msg(&outcome.error_message);
            warn!(
                "[{}] upstream rejected tx (code {}): {reason}",
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

    /// `walletpassphrase`: decrypt the seed with `passphrase` and hold it unlocked until
    /// `timeout_secs` from now (argument validation/clamping happens in the RPC layer). Only
    /// valid for an encrypted wallet; an unencrypted one returns -15 like Bitcoin Core.
    fn do_unlock(
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
        let st = store::WalletStore::read(&self.wallet_dir)
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

    /// `encryptwallet`: re-wrap the (currently identity-encrypted or KMS-wrapped) mnemonic
    /// under `passphrase` and leave the wallet locked. -15 if already encrypted. Unlike
    /// Bitcoin Core, the seed is NOT regenerated - the same mnemonic is preserved, only its
    /// at-rest wrapping changes. For a KMS wallet this is the migration path *off* the
    /// cloud keystore (the `[kms]` table is dropped from `keys.toml`).
    async fn do_encrypt_wallet(&mut self, passphrase: store::Passphrase) -> Result<(), RpcError> {
        // A watch-only wallet stores no mnemonic at all; there is nothing to wrap under a
        // passphrase (the UFVK must stay readable for scanning). Bitcoin Core's exact refusal
        // for wallets without private keys is -16, not the generic -4 (wallet/rpc/encrypt.cpp).
        if self.watch_only {
            return Err(RpcError::new(
                codes::RPC_WALLET_ENCRYPTION_FAILED,
                "Error: wallet does not contain private keys, nothing to encrypt.",
            ));
        }
        if self.encrypted {
            return Err(RpcError::new(
                codes::RPC_WALLET_WRONG_ENC_STATE,
                "Error: running with an encrypted wallet, but encryptwallet was called.",
            ));
        }
        let st = store::WalletStore::read(&self.wallet_dir)
            .map_err(|e| RpcError::wallet(format!("reading keys.toml: {e}")))?;
        let mnemonic = if self.kms_wallet {
            keys::decrypt_mnemonic_with_keystore(&st, self.keystore_endpoint.as_deref())
                .await
                .map_err(|e| RpcError::wallet(format!("decrypting mnemonic via KMS: {e:#}")))?
        } else {
            let identity = self.age_identity.as_ref().ok_or_else(|| {
                RpcError::wallet("no age identity configured; cannot read the mnemonic to encrypt")
            })?;
            keys::decrypt_mnemonic_with_identity(&st, identity)
                .map_err(|e| RpcError::wallet(format!("decrypting mnemonic: {e}")))?
        };
        let mnemonic = mnemonic.ok_or_else(|| RpcError::wallet("wallet has no stored mnemonic"))?;
        let phrase = std::str::from_utf8(mnemonic.expose_secret().as_slice())
            .map_err(|_| RpcError::wallet("stored mnemonic is not valid UTF-8"))?;
        // scrypt key derivation for the new wrapping is deliberately slow; keep it off the
        // async runtime (the proving pattern).
        tokio::task::block_in_place(|| {
            st.rewrite_with_passphrase(&self.wallet_dir, passphrase, phrase)
        })
        .map_err(|e| {
            RpcError::new(
                codes::RPC_WALLET_ENCRYPTION_FAILED,
                format!("failed to encrypt wallet: {e}"),
            )
        })?;
        // Now Bitcoin-Core "encrypted": lock and require walletpassphrase from here on.
        // A former KMS wallet stops being one (keys.toml no longer carries the [kms] table).
        self.encrypted = true;
        self.kms_wallet = false;
        self.kms_unlock_retry = None;
        self.seed.lock();
        self.unlock_until = None;
        self.update_status();
        Ok(())
    }

    /// `walletpassphrasechange`: re-wrap the mnemonic from `old` to `new`. -15 if unencrypted,
    /// -14 if `old` is wrong. Does not change the current lock state.
    fn do_change_passphrase(
        &mut self,
        old: store::Passphrase,
        new: store::Passphrase,
    ) -> Result<(), RpcError> {
        if !self.encrypted {
            return Err(RpcError::new(
                codes::RPC_WALLET_WRONG_ENC_STATE,
                "Error: running with an unencrypted wallet, but walletpassphrasechange was called.",
            ));
        }
        let st = store::WalletStore::read(&self.wallet_dir)
            .map_err(|e| RpcError::wallet(format!("reading keys.toml: {e}")))?;
        // Both the old-passphrase verification and the new wrapping run scrypt (deliberately
        // slow); keep them off the async runtime (the proving pattern).
        let mnemonic = tokio::task::block_in_place(|| st.decrypt_mnemonic_with_passphrase(old))
            .map_err(|_| {
                RpcError::new(
                    codes::RPC_WALLET_PASSPHRASE_INCORRECT,
                    "Error: The wallet passphrase entered was incorrect.",
                )
            })?
            .ok_or_else(|| RpcError::wallet("wallet has no stored mnemonic"))?;
        let phrase = std::str::from_utf8(mnemonic.expose_secret().as_slice())
            .map_err(|_| RpcError::wallet("stored mnemonic is not valid UTF-8"))?;
        tokio::task::block_in_place(|| st.rewrite_with_passphrase(&self.wallet_dir, new, phrase))
            .map_err(|e| {
            RpcError::new(
                codes::RPC_WALLET_ENCRYPTION_FAILED,
                format!("failed to change passphrase: {e}"),
            )
        })?;
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
}
