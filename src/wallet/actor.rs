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
    create_proposed_transactions, input_selection::GreedyInputSelector, propose_transfer,
    ConfirmationsPolicy, SpendingKeys,
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
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::BlockHeight;
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
    account_id: AccountUuid,
    account_index: Option<zip32::AccountId>,
    db_data: WriteDb,
    db_cache: FsBlockDb,
    client: Option<CompactTxStreamerClient<Channel>>,
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
}

/// Open the wallet, derive its account info, optionally unlock the seed, build the prover,
/// and spawn the actor task. Returns a clonable handle.
pub async fn spawn(cfg: ActorConfig) -> anyhow::Result<WalletHandle> {
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
        last_rebroadcast: None,
        subtree_roots_synced: false,
        encrypted,
        unlock_until: None,
    };

    tokio::spawn(actor.run());

    Ok(make_handle(
        cfg.name,
        cfg.wallet_dir,
        cfg.network,
        cmd_tx,
        status_rx,
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
                            // Caught up: give any unmined wallet txs another shot at the mempool.
                            self.maybe_rebroadcast().await;
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
                tokio::select! {
                    maybe_cmd = self.cmd_rx.recv() => {
                        match maybe_cmd {
                            Some(cmd) => if self.handle_command(cmd).await { return; },
                            None => return,
                        }
                    }
                    _ = relock_sleep(self.unlock_until) => {
                        self.relock_if_expired();
                    }
                    _ = tokio::time::sleep(wait) => {
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
                }
            }
        }
    }

    /// Connect to lightwalletd, always preferring the primary: try the configured endpoints in
    /// order from the top and use the first that connects (and passes the subtree-root sync). On
    /// success, store the client, record the active server, and reset the reconnect backoff. On
    /// total failure, leave `self.client` as `None` and return the last error.
    async fn connect(&mut self) -> anyhow::Result<()> {
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
            self.active = idx;
            self.backoff.reset();
            self.update_status();
            return;
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
                self.db_data.get_wallet_summary(ConfirmationsPolicy::default())
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
                    ConfirmationsPolicy::default(),
                    None,
                )
                .map_err(classify_err)?;

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
                .map_err(classify_err)?;

                if txids.len() > 1 {
                    return Err(RpcError::wallet(
                        "multi-transaction proposals are not supported",
                    ));
                }
                let txid = *txids.first();

                let tx = db
                    .get_transaction(txid)
                    .map_err(|e| RpcError::database(e.to_string()))?
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
            return Err(RpcError::new(
                codes::RPC_VERIFY_REJECTED,
                format!(
                    "transaction rejected (code {}): {}",
                    response.error_code, response.error_message
                ),
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
            return Err(RpcError::new(
                codes::RPC_VERIFY_REJECTED,
                format!(
                    "transaction rejected (code {}): {}",
                    response.error_code, response.error_message
                ),
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
        let seed = st
            .decrypt_seed_with_passphrase(passphrase)
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
        st.rewrite_with_passphrase(&self.wallet_dir, passphrase, phrase)
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
        let mnemonic = st
            .decrypt_mnemonic_with_passphrase(old)
            .map_err(|_| {
                RpcError::new(
                    codes::RPC_WALLET_PASSPHRASE_INCORRECT,
                    "Error: The wallet passphrase entered was incorrect.",
                )
            })?
            .ok_or_else(|| RpcError::wallet("wallet has no stored mnemonic"))?;
        let phrase = std::str::from_utf8(mnemonic.expose_secret().as_slice())
            .map_err(|_| RpcError::wallet("stored mnemonic is not valid UTF-8"))?;
        st.rewrite_with_passphrase(&self.wallet_dir, new, phrase)
            .map_err(|e| {
                RpcError::new(
                    codes::RPC_WALLET_ENCRYPTION_FAILED,
                    format!("failed to change passphrase: {e}"),
                )
            })?;
        Ok(())
    }
}

/// Ensure a freshly-connected lightwalletd `client` is healthy and the wallet has its
/// note-commitment subtree roots. The first successful call this process downloads the roots
/// (also a health check) and sets `roots_synced`; subsequent calls only do a cheap
/// `get_latest_block` liveness probe, since the roots already persist in the wallet DB. This
/// avoids re-streaming every subtree root on each reconnect / primary re-probe.
///
/// The whole check is bounded by `budget`: a peer that accepts connections but never answers
/// (the dial timeout can't see this) must not stall the actor's command loop.
async fn prepare_client(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WriteDb,
    roots_synced: &mut bool,
    budget: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(budget, async {
        if *roots_synced {
            client.get_latest_block(service::ChainSpec::default()).await?;
        } else {
            engine::update_subtree_roots(client, db_data).await?;
            *roots_synced = true;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("upstream health check timed out after {budget:?}"))?
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
