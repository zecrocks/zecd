//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use secrecy::ExposeSecret;
use tokio::sync::{mpsc, watch};
use tonic::transport::Channel;
use tracing::{info, warn};

use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, decrypt_and_store_transaction,
    input_selection::GreedyInputSelector, propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{Account, WalletRead, WalletWrite};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
};
use zcash_client_backend::proto::service::{
    self, compact_tx_streamer_client::CompactTxStreamerClient,
};
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

/// Parameters needed to launch a wallet actor.
pub struct ActorConfig {
    pub name: String,
    pub network: ZNetwork,
    pub wallet_dir: PathBuf,
    /// Ordered lightwalletd endpoints (non-empty); tried in order, preferring the first.
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
    /// Ordered lightwalletd endpoints (non-empty); `active` indexes the connected one.
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
    client: Option<CompactTxStreamerClient<Channel>>,
    /// Live mempool subscription (`GetMempoolStream`), open only while caught up to the tip.
    /// lightwalletd streams current + newly-arriving mempool txs and closes the stream when a
    /// new block is mined; each tx is trial-decrypted and stored unmined if it pays this
    /// wallet, which is what lets `getunconfirmedbalance`/`listtransactions` reflect an
    /// incoming payment before its first confirmation (bitcoind parity). Best-effort: any
    /// stream error just drops it and the next caught-up pass reopens.
    mempool: Option<tonic::Streaming<service::RawTransaction>>,
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
    /// For an encrypted wallet that's currently unlocked: when the seed auto-relocks. Re-running
    /// `walletpassphrase` overwrites it (resetting the timer); `walletlock` clears it.
    unlock_until: Option<Instant>,
    /// Graceful-shutdown signal (see [`ActorConfig::shutdown`]).
    shutdown: watch::Receiver<bool>,
}

/// Open the wallet, derive its account info, optionally unlock the seed, build the prover,
/// and spawn the actor task. Returns a clonable handle plus the task's join handle (awaited
/// at shutdown so the wallet DB closes cleanly before the runtime is torn down).
pub async fn spawn(cfg: ActorConfig) -> anyhow::Result<(WalletHandle, tokio::task::JoinHandle<()>)> {
    if cfg.servers.is_empty() {
        return Err(anyhow!(
            "no lightwalletd servers configured for wallet '{}'",
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
    let (account_id, account_index) = select_account(&db_data)?;

    // Determine the wallet's encryption mode, and for unencrypted wallets optionally decrypt
    // the seed up-front for unattended sending. An encrypted wallet has no passphrase at rest,
    // so it cannot auto-unlock - it starts locked and requires `walletpassphrase` (matching
    // Bitcoin Core's encrypted-wallet behavior).
    let st = store::WalletStore::read(&cfg.wallet_dir)?;
    let encrypted = st.is_encrypted();
    let mut seed = SeedKeeper::locked();
    if encrypted {
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
    let (status_tx, status_rx) = watch::channel(SyncStatus::default());

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

fn select_account(db: &WriteDb) -> anyhow::Result<(AccountUuid, Option<zip32::AccountId>)> {
    let ids = db.get_account_ids()?;
    let id = *ids
        .first()
        .ok_or_else(|| anyhow!("wallet has no accounts; run `zecd init` first"))?;
    let account = db
        .get_account(id)?
        .ok_or_else(|| anyhow!("selected account not found"))?;
    let index = account.source().key_derivation().map(|d| d.account_index());
    Ok((id, index))
}

impl WalletActor {
    async fn run(mut self) {
        if let Err(e) = self.connect().await {
            warn!("[{}] initial lightwalletd connect failed: {e}", self.name);
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
                            if self.handle_command(cmd).await {
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
                    Mempool(Result<Option<service::RawTransaction>, tonic::Status>),
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
                        if self.handle_command(cmd).await {
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
                                warn!("[{}] reconnect failed: {e}; retrying in {delay:?}", self.name);
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
                    IdleEvent::Mempool(Ok(Some(raw))) => self.store_mempool_tx(raw),
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

    /// Connect to lightwalletd, always preferring the primary: try the configured endpoints in
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
            info!("[{}] connecting to lightwalletd {}", self.name, describe);
            match self.servers[idx].connect_timeout(self.connect_timeout).await {
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
                            "[{}] lightwalletd now using {} (was {})",
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
                warn!("[{}] primary re-probe {} not healthy: {e}", self.name, describe);
                continue;
            }
            info!(
                "[{}] preferred lightwalletd {} recovered; switching back from {}",
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

    /// Subscribe to lightwalletd's mempool stream if not already subscribed. Called only when
    /// caught up to the chain tip (mempool txs are meaningless to a wallet that's still
    /// scanning history). Failures are logged at debug and retried on the next caught-up
    /// pass - older or unusual upstreams may not serve `GetMempoolStream`, and 0-conf
    /// visibility is a best-effort improvement, not a correctness requirement.
    async fn ensure_mempool_stream(&mut self) {
        if self.mempool.is_some() || self.tip_height.is_none() {
            return;
        }
        let Some(client) = self.client.as_mut() else { return };
        // Bounded like other unary calls: only the response headers are awaited here; the
        // stream body is consumed incrementally from the idle loop.
        match tokio::time::timeout(
            UNARY_RPC_TIMEOUT,
            client.get_mempool_stream(service::Empty::default()),
        )
        .await
        {
            Ok(Ok(stream)) => {
                tracing::debug!("[{}] subscribed to the mempool stream", self.name);
                self.mempool = Some(stream.into_inner());
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
                    if let Err(e) = super::labels::record_first_seen(&self.wallet_dir, &txid_hex, now)
                    {
                        tracing::debug!("[{}] failed to record first-seen time: {e}", self.name);
                    }
                }
            }
            Err(e) => warn!("[{}] failed to store mempool tx {txid}: {e}", self.name),
        }
    }

    async fn refresh_tip(&mut self) -> anyhow::Result<()> {
        let block_id = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| anyhow!("not connected"))?;
            tokio::time::timeout(
                UNARY_RPC_TIMEOUT,
                client.get_latest_block(service::ChainSpec::default()),
            )
            .await
            .map_err(|_| anyhow!("get_latest_block timed out after {UNARY_RPC_TIMEOUT:?}"))??
            .into_inner()
        };
        let tip = BlockHeight::try_from(block_id.height)
            .map_err(|_| anyhow!("chain tip height out of range"))?;
        self.db_data.update_chain_tip(tip)?;
        self.tip_height = Some(u32::from(tip));
        if block_id.hash.len() == 32 {
            let mut h = block_id.hash.clone();
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
            let Some(client) = self.client.as_mut() else { return };
            let raw = service::RawTransaction { data, ..Default::default() };
            let sent = tokio::time::timeout(UNARY_RPC_TIMEOUT, client.send_transaction(raw))
                .await
                .map_err(|_| {
                    tonic::Status::deadline_exceeded(format!(
                        "rebroadcast timed out after {UNARY_RPC_TIMEOUT:?}"
                    ))
                })
                .and_then(|r| r);
            match sent {
                Ok(r) => {
                    let r = r.into_inner();
                    if r.error_code == 0 {
                        info!("[{}] re-broadcast unmined tx {txid}", self.name);
                    } else {
                        tracing::debug!(
                            "[{}] rebroadcast of {txid} rejected (code {}): {}",
                            self.name,
                            r.error_code,
                            r.error_message
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
            WalletCommand::Send { request, reply } => {
                let res = self.do_send(request).await;
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
            WalletCommand::Unlock { passphrase, timeout_secs, reply } => {
                let res = self.do_unlock(passphrase, timeout_secs);
                let _ = reply.send(res);
            }
            WalletCommand::Lock { reply } => {
                let res = self.do_lock();
                let _ = reply.send(res);
            }
            WalletCommand::EncryptWallet { passphrase, reply } => {
                let res = self.do_encrypt_wallet(passphrase);
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
            info!("[{}] wallet auto-locked (walletpassphrase timeout elapsed)", self.name);
            self.update_status();
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

    async fn do_send(&mut self, request: TransactionRequest) -> Result<TxId, RpcError> {
        // Hard backstop: if an encrypted wallet's unlock has expired but proactive relock
        // hasn't fired yet (e.g. a long sync batch was in progress), lock now so the spend
        // can't slip through past its timeout. `derive_usk` then returns -13 as expected.
        self.relock_if_expired();
        let account_index = self
            .account_index
            .ok_or_else(|| RpcError::wallet("Cannot spend from a view-only account"))?;
        let usk = self.seed.derive_usk(self.network, account_index)?;

        // Proposal building + proving is CPU-heavy (Sapling/Orchard proofs take seconds).
        // Run it under `block_in_place` so it doesn't stall the async runtime, and so the
        // single send doesn't block the actor thread from being cooperatively yielded.
        let net = self.network;
        let account_id = self.account_id;
        let policy = self.confirmations_policy;
        let prover = &self.prover;
        let db = &mut self.db_data;
        let (txid, raw): (TxId, service::RawTransaction) =
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
                let mut raw_tx = service::RawTransaction::default();
                tx.write(&mut raw_tx.data)
                    .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;
                Ok((txid, raw_tx))
            })?;

        // The transaction is now committed to the wallet DB (its input notes are locked until
        // expiry) and `maybe_rebroadcast` keeps re-submitting it while it is unmined and
        // unexpired. From here on, a transport-level broadcast failure must NOT surface as an
        // RPC error: bitcoind's contract is that once the wallet has committed the tx,
        // `sendtoaddress` returns the txid even if initial relay fails - returning an error
        // here would invite the caller to retry the payment while the original can still be
        // re-broadcast and confirm (an application-level double-pay).
        if self.client.is_none() {
            if let Err(e) = self.connect().await {
                warn!(
                    "[{}] created {txid} but no lightwalletd is reachable ({e}); it will be \
                     re-broadcast once a connection recovers",
                    self.name
                );
                return Ok(txid);
            }
        }
        let response = {
            let client = self.client.as_mut().expect("connected above");
            // Bounded: a peer that hangs mid-broadcast is treated like any other transport
            // failure - the committed tx rides on the rebroadcast loop either way.
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.send_transaction(raw))
                .await
                .map_err(|_| {
                    tonic::Status::deadline_exceeded(format!(
                        "broadcast timed out after {UNARY_RPC_TIMEOUT:?}"
                    ))
                })
                .and_then(|r| r)
        };
        let response = match response {
            Ok(r) => r.into_inner(),
            Err(e) => {
                // Transport failure: drop the dead client so the next op reconnects/fails over.
                // The committed tx rides on the rebroadcast loop.
                self.client = None;
                self.update_status();
                warn!(
                    "[{}] broadcast of {txid} failed in transport ({e}); it will be re-broadcast",
                    self.name
                );
                return Ok(txid);
            }
        };
        if response.error_code != 0 {
            // An explicit upstream rejection (the node examined the tx and refused it) is a
            // different case from a transport failure: surface it as -26. The tx's notes stay
            // locked in the wallet until its expiry height, after which they become spendable
            // again - an immediate retry fails with -6 rather than double-paying.
            let reason = sanitize_upstream_msg(&response.error_message);
            warn!("[{}] upstream rejected {txid} (code {}): {reason}", self.name, response.error_code);
            return Err(RpcError::new(
                codes::RPC_VERIFY_REJECTED,
                format!("transaction rejected (code {}): {reason}", response.error_code),
            ));
        }

        self.update_status();
        Ok(txid)
    }

    /// Return raw transaction bytes: prefer the locally-stored copy (present for txs we
    /// created or have enhanced), otherwise fetch the full tx from lightwalletd. The
    /// `TxFilter` hash is the txid's internal bytes (per zcash-devtool's enhance).
    async fn do_get_raw_tx(&mut self, txid: TxId) -> Result<Option<RawTx>, RpcError> {
        if let Ok(Some(tx)) = self.db_data.get_transaction(txid) {
            let mut buf = Vec::new();
            tx.write(&mut buf)
                .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;
            return Ok(Some(RawTx { data: buf, mined_height: None }));
        }
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to lightwalletd: {e}")))?;
        }
        let filter = service::TxFilter {
            hash: txid.as_ref().to_vec(),
            ..Default::default()
        };
        let raw = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| RpcError::misc("not connected to lightwalletd"))?;
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.get_transaction(filter))
                .await
                .map_err(|_| {
                    tonic::Status::deadline_exceeded(format!(
                        "get_transaction timed out after {UNARY_RPC_TIMEOUT:?}"
                    ))
                })
                .and_then(|r| r)
        };
        let raw = match raw {
            Ok(r) => r.into_inner(),
            // The upstream looked up the txid and doesn't know it: an application-level
            // miss, not a failure - keep the (healthy) client and report "no such tx".
            Err(status) if is_tx_not_found(&status) => return Ok(None),
            Err(e) => {
                // Transport failure: drop the dead client so the next op reconnects/fails over.
                self.client = None;
                self.update_status();
                return Err(RpcError::misc(format!("get_transaction RPC failed: {e}")));
            }
        };
        Ok(if raw.data.is_empty() {
            None
        } else {
            // lightwalletd reports the mined height in `height`; mempool transactions carry
            // 0 or -1 (encoded as u64), neither of which is a real mined height here.
            let mined_height = u32::try_from(raw.height).ok().filter(|h| *h > 0);
            Some(RawTx { data: raw.data, mined_height })
        })
    }

    /// Broadcast caller-supplied raw transaction bytes (`sendrawtransaction`). Unlike
    /// `do_send`, the transaction is not in our wallet DB, so there is no rebroadcast loop
    /// backing it - every failure (transport or rejection) surfaces as an error so the
    /// caller knows the network never accepted the tx.
    async fn do_broadcast(&mut self, data: Vec<u8>) -> Result<(), RpcError> {
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to lightwalletd: {e}")))?;
        }
        let raw = service::RawTransaction { data, ..Default::default() };
        let response = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| RpcError::misc("not connected to lightwalletd"))?;
            tokio::time::timeout(UNARY_RPC_TIMEOUT, client.send_transaction(raw))
                .await
                .map_err(|_| {
                    tonic::Status::deadline_exceeded(format!(
                        "broadcast timed out after {UNARY_RPC_TIMEOUT:?}"
                    ))
                })
                .and_then(|r| r)
        };
        let response = match response {
            Ok(r) => r.into_inner(),
            Err(e) => {
                // Transport/deadline failure: drop the client so the next op reconnects/fails over.
                self.client = None;
                self.update_status();
                return Err(RpcError::misc(format!("send_transaction RPC failed: {e}")));
            }
        };
        if response.error_code != 0 {
            let reason = sanitize_upstream_msg(&response.error_message);
            warn!("[{}] upstream rejected tx (code {}): {reason}", self.name, response.error_code);
            return Err(RpcError::new(
                codes::RPC_VERIFY_REJECTED,
                format!("transaction rejected (code {}): {reason}", response.error_code),
            ));
        }
        Ok(())
    }

    /// `walletpassphrase`: decrypt the seed with `passphrase` and hold it unlocked until
    /// `timeout_secs` from now (argument validation/clamping happens in the RPC layer). Only
    /// valid for an encrypted wallet; an unencrypted one returns -15 like Bitcoin Core.
    fn do_unlock(&mut self, passphrase: store::Passphrase, timeout_secs: i64) -> Result<(), RpcError> {
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

    /// `encryptwallet`: re-wrap the (currently identity-encrypted) mnemonic under `passphrase`
    /// and leave the wallet locked. -15 if already encrypted. Unlike Bitcoin Core, the seed is
    /// NOT regenerated - the same mnemonic is preserved, only its at-rest wrapping changes.
    fn do_encrypt_wallet(&mut self, passphrase: store::Passphrase) -> Result<(), RpcError> {
        if self.encrypted {
            return Err(RpcError::new(
                codes::RPC_WALLET_WRONG_ENC_STATE,
                "Error: running with an encrypted wallet, but encryptwallet was called.",
            ));
        }
        let identity = self.age_identity.as_ref().ok_or_else(|| {
            RpcError::wallet("no age identity configured; cannot read the mnemonic to encrypt")
        })?;
        let st = store::WalletStore::read(&self.wallet_dir)
            .map_err(|e| RpcError::wallet(format!("reading keys.toml: {e}")))?;
        let mnemonic = keys::decrypt_mnemonic_with_identity(&st, identity)
            .map_err(|e| RpcError::wallet(format!("decrypting mnemonic: {e}")))?
            .ok_or_else(|| RpcError::wallet("wallet has no stored mnemonic"))?;
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
        self.encrypted = true;
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

/// Ensure a freshly-connected lightwalletd `client` is healthy, serves the chain this wallet
/// is configured for, and the wallet has its note-commitment subtree roots. The
/// `get_lightd_info` call doubles as the liveness probe and the wrong-chain guard (a mainnet
/// zecd pointed at a testnet lightwalletd would otherwise happily scan the wrong chain). The
/// first successful call this process additionally downloads the subtree roots and sets
/// `roots_synced`; the roots persist in the wallet DB, so they aren't re-streamed on each
/// reconnect / primary re-probe.
///
/// The whole check is bounded by `budget`: a peer that accepts connections but never answers
/// (the dial timeout can't see this) must not stall the actor's command loop.
async fn prepare_client(
    client: &mut CompactTxStreamerClient<Channel>,
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

/// Refuse a lightwalletd whose `chain_name` contradicts the configured network. Only the
/// mainnet/non-mainnet boundary is enforced: zebra reports `"test"` for regtest too (its
/// `bip70_network_name` only distinguishes mainnet), so test vs regtest cannot be told
/// apart from here - and the guard's job is ensuring a mainnet wallet never scans a test
/// chain (or vice versa). A definitive cross is a hard error so the caller fails over to
/// the next candidate; an unrecognized name is only a warning, since not every server
/// reports one.
async fn verify_server_network(
    client: &mut CompactTxStreamerClient<Channel>,
    network: ZNetwork,
) -> anyhow::Result<()> {
    let info = client.get_lightd_info(service::Empty {}).await?.into_inner();
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

/// Bound an upstream-supplied string before echoing it into an RPC error. lightwalletd's
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

/// Await the next message on an open mempool stream, or pend forever when none is open, so
/// the actor's idle `select!` arm simply never fires without a subscription.
async fn mempool_next(
    stream: &mut Option<tonic::Streaming<service::RawTransaction>>,
) -> Result<Option<service::RawTransaction>, tonic::Status> {
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
        Error::InsufficientFunds { available, required } => {
            RpcError::insufficient_funds(format!(
                "Insufficient funds: {} zatoshis spendable, {} required (including fee)",
                u64::from(*available),
                u64::from(*required),
            ))
        }
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
        incoming += bal.orchard_balance().value_pending_spendability().into_u64()
            + bal.sapling_balance().value_pending_spendability().into_u64();
        change += bal.orchard_balance().change_pending_confirmation().into_u64()
            + bal.sapling_balance().change_pending_confirmation().into_u64();
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

/// True when a `GetTransaction` error status means the node simply does not know the txid -
/// an application-level miss the RPC layer reports as -5, not a transport failure worth
/// dropping the connection over. lightwalletd proxies the backing node's message through:
/// zcashd says "No such mempool transaction" / "No such mempool or blockchain transaction"
/// (with -txindex) or, historically, "No information available about transaction"; zebrad
/// says "No such mempool or main chain transaction".
fn is_tx_not_found(status: &tonic::Status) -> bool {
    if status.code() == tonic::Code::NotFound {
        return true;
    }
    let msg = status.message().to_lowercase();
    msg.contains("no such mempool") || msg.contains("no information available about transaction")
}

#[cfg(test)]
mod tests {
    use super::{is_tx_not_found, sanitize_upstream_msg};

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

    #[test]
    fn tx_not_found_statuses_are_misses_not_failures() {
        for msg in [
            "No such mempool transaction. Use -txindex to enable blockchain transaction queries.",
            "No such mempool or blockchain transaction",
            "No such mempool or main chain transaction",
            "-5: No such mempool or main chain transaction",
            "No information available about transaction",
        ] {
            assert!(
                is_tx_not_found(&tonic::Status::unknown(msg)),
                "{msg:?} must classify as not-found"
            );
        }
        assert!(is_tx_not_found(&tonic::Status::not_found("anything")));
        // Transport-class failures must still drop the client.
        assert!(!is_tx_not_found(&tonic::Status::unavailable("connection refused")));
        assert!(!is_tx_not_found(&tonic::Status::deadline_exceeded("timed out")));
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
        assert_eq!(chain_name_is_main("test"), Some(is_main(crate::network::regtest())));
        // The boundary that matters: a mainnet wallet rejects test chains and vice versa.
        assert_ne!(chain_name_is_main("test"), Some(is_main(super::ZNetwork::Main)));
        assert_ne!(chain_name_is_main("main"), Some(is_main(super::ZNetwork::Test)));
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
        db.create_account("t", &secrecy::SecretVec::new(vec![1u8; 64]), &birthday, None)
            .expect("create account");
        // The tip must be set before `get_wallet_summary` (progress-estimator underflow
        // gotcha); the production call site inherits this from the completed proposal.
        db.update_chain_tip(BlockHeight::from_u32(5)).expect("set tip");

        let other = RpcError::wallet("some other failure");
        assert_eq!(super::enrich_insufficient_funds(&db, Default::default(), other.clone()).message, other.message);

        let bare = RpcError::insufficient_funds("Insufficient funds: 0 zatoshis spendable");
        let out = super::enrich_insufficient_funds(&db, Default::default(), bare.clone());
        assert_eq!(out.code, codes::RPC_WALLET_INSUFFICIENT_FUNDS);
        assert_eq!(out.message, bare.message, "no pending balance, so no enrichment");
    }
}
