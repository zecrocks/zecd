//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
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

use crate::error::{codes, RpcError};
use crate::lightwalletd::Server;
use crate::network::ZNetwork;
use crate::sync::engine;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::{labels, make_handle, store, SyncStatus, WalletCommand, WalletHandle};

/// Note-management defaults for change splitting (match zcash-devtool's send defaults).
const TARGET_NOTE_COUNT: usize = 4;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000; // 0.1 ZEC

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
    pub server: Server,
    pub sync_interval: Duration,
    pub age_identity: Option<PathBuf>,
    pub auto_unlock: bool,
}

struct WalletActor {
    name: String,
    network: ZNetwork,
    wallet_dir: PathBuf,
    server: Server,
    sync_interval: Duration,
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
    tip_time: Option<i64>,
}

/// Open the wallet, derive its account info, optionally unlock the seed, build the prover,
/// and spawn the actor task. Returns a clonable handle.
pub async fn spawn(cfg: ActorConfig) -> anyhow::Result<WalletHandle> {
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

    // Optionally decrypt the seed up-front for unattended sending.
    let mut seed = SeedKeeper::locked();
    if cfg.auto_unlock {
        if let Some(identity) = &cfg.age_identity {
            let st = store::WalletStore::read(&cfg.wallet_dir)?;
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
        server: cfg.server,
        sync_interval: cfg.sync_interval,
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
        tip_time: None,
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

        let mut interval = tokio::time::interval(self.sync_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut more_work = true;
        loop {
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
                    Ok(worked) => more_work = worked,
                    Err(e) => {
                        warn!("[{}] sync error: {e}", self.name);
                        self.client = None;
                        self.update_status();
                        more_work = false;
                    }
                }
            } else {
                tokio::select! {
                    maybe_cmd = self.cmd_rx.recv() => {
                        match maybe_cmd {
                            Some(cmd) => if self.handle_command(cmd).await { return; },
                            None => return,
                        }
                    }
                    _ = interval.tick() => {
                        if self.client.is_none() {
                            if let Err(e) = self.connect().await {
                                warn!("[{}] reconnect failed: {e}", self.name);
                            }
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

    async fn connect(&mut self) -> anyhow::Result<()> {
        info!(
            "[{}] connecting to lightwalletd {}",
            self.name,
            self.server.describe()
        );
        let client = self.server.connect().await?;
        self.client = Some(client);
        let client = self.client.as_mut().expect("just set");
        engine::update_subtree_roots(client, &mut self.db_data).await?;
        // NB: do not call `update_status()` here - `get_wallet_summary`'s progress estimator
        // underflows if invoked before the chain tip is set (see `refresh_tip`).
        Ok(())
    }

    async fn refresh_tip(&mut self) -> anyhow::Result<()> {
        let block_id = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| anyhow!("not connected"))?;
            client
                .get_latest_block(service::ChainSpec::default())
                .await?
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

        let status = SyncStatus {
            connected: self.client.is_some(),
            chain_tip: self.tip_height,
            fully_scanned,
            best_block_hash: self.tip_hash.clone(),
            scan_progress,
            scanning,
            tip_time: self.tip_time,
        };
        let _ = self.status_tx.send(status);
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
            WalletCommand::Unlock { reply } => {
                let res = self.do_unlock();
                let _ = reply.send(res);
            }
            WalletCommand::Lock { reply } => {
                self.seed.lock();
                let _ = reply.send(Ok(()));
            }
        }
        false
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
                )
                .map_err(|e: crate::error::ProposalError| classify_err(e))?;

                let txids = create_proposed_transactions(
                    db,
                    &net,
                    prover,
                    prover,
                    &SpendingKeys::from_unified_spending_key(usk),
                    OvkPolicy::Sender,
                    &proposal,
                )
                .map_err(|e: crate::error::ProposalError| classify_err(e))?;

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

        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to lightwalletd: {e}")))?;
        }
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| RpcError::misc("not connected to lightwalletd"))?;
        let response = client
            .send_transaction(raw)
            .await
            .map_err(|e| RpcError::misc(format!("send_transaction RPC failed: {e}")))?
            .into_inner();
        if response.error_code != 0 {
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
    async fn do_get_raw_tx(&mut self, txid: TxId) -> Result<Option<Vec<u8>>, RpcError> {
        if let Ok(Some(tx)) = self.db_data.get_transaction(txid) {
            let mut buf = Vec::new();
            tx.write(&mut buf)
                .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;
            return Ok(Some(buf));
        }
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to lightwalletd: {e}")))?;
        }
        let client = self
            .client
            .as_mut()
            .ok_or_else(|| RpcError::misc("not connected to lightwalletd"))?;
        let filter = service::TxFilter {
            hash: txid.as_ref().to_vec(),
            ..Default::default()
        };
        let raw = client
            .get_transaction(filter)
            .await
            .map_err(|e| RpcError::misc(format!("get_transaction RPC failed: {e}")))?
            .into_inner();
        Ok(if raw.data.is_empty() { None } else { Some(raw.data) })
    }

    fn do_unlock(&mut self) -> Result<(), RpcError> {
        if self.seed.is_unlocked() {
            return Ok(());
        }
        let identity = self
            .age_identity
            .as_ref()
            .ok_or_else(|| RpcError::wallet("no age identity configured; cannot unlock wallet"))?;
        let st = store::WalletStore::read(&self.wallet_dir)
            .map_err(|e| RpcError::wallet(format!("reading keys.toml: {e}")))?;
        let seed = keys::decrypt_seed_with_identity(&st, identity)
            .map_err(|e| RpcError::wallet(format!("decrypting seed: {e}")))?
            .ok_or_else(|| RpcError::wallet("wallet has no stored seed"))?;
        self.seed.set(seed);
        Ok(())
    }
}

/// Classify a librustzcash spend/proposal error into a Bitcoin-Core RPC code. Insufficient
/// funds maps to -6; everything else to the generic wallet error -4.
fn classify_err<E: std::fmt::Debug>(e: E) -> RpcError {
    let s = format!("{e:?}");
    if s.to_lowercase().contains("insufficient") {
        RpcError::insufficient_funds(s)
    } else {
        RpcError::wallet(s)
    }
}
