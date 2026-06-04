//! Wallet management: the single-writer actor, the clonable handle used by RPC handlers,
//! and the multiwallet registry.

pub mod actor;
pub mod keys;
pub mod labels;
pub mod open;
pub mod read;
pub mod store;

use std::collections::HashMap;
use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot, watch};
use zcash_protocol::consensus::Network;
use zcash_protocol::TxId;
use zip321::TransactionRequest;

use crate::error::RpcError;

/// A snapshot of sync state, published by the actor and read by blockchain/wallet RPCs.
#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    pub connected: bool,
    pub chain_tip: Option<u32>,
    pub fully_scanned: Option<u32>,
    pub best_block_hash: Option<String>,
    /// Scan progress in `[0, 1]`.
    pub scan_progress: f64,
    pub scanning: bool,
    pub tip_time: Option<i64>,
}

impl SyncStatus {
    /// Confirmations for a transaction mined at `mined_height` given the current tip.
    pub fn confirmations(&self, mined_height: Option<u32>) -> i64 {
        match (self.chain_tip, mined_height) {
            (Some(tip), Some(h)) if tip >= h => (tip - h + 1) as i64,
            _ => 0,
        }
    }
}

/// Commands sent from RPC handlers to the per-wallet actor (the sole DB writer).
pub enum WalletCommand {
    GetNewAddress {
        label: Option<String>,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    Send {
        request: TransactionRequest,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    },
    /// Decrypt the seed into memory (compat for `walletpassphrase`).
    Unlock {
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Zeroize the in-memory seed (compat for `walletlock`).
    Lock {
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
}

/// A clonable, `Send + Sync` handle to one wallet. RPC handlers use it to issue writer
/// commands (via the actor) and to read the published [`SyncStatus`]. Read-only queries are
/// served directly from short-lived connections (see [`read`]).
#[derive(Clone)]
pub struct WalletHandle {
    pub name: String,
    pub dir: PathBuf,
    pub network: Network,
    cmd_tx: mpsc::Sender<WalletCommand>,
    status_rx: watch::Receiver<SyncStatus>,
}

impl WalletHandle {
    pub fn status(&self) -> SyncStatus {
        self.status_rx.borrow().clone()
    }

    async fn dispatch<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, RpcError>>) -> WalletCommand,
    ) -> Result<T, RpcError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(make(tx))
            .await
            .map_err(|_| RpcError::misc("wallet actor is not running"))?;
        rx.await
            .map_err(|_| RpcError::misc("wallet actor dropped the reply"))?
    }

    pub async fn get_new_address(&self, label: Option<String>) -> Result<String, RpcError> {
        self.dispatch(|reply| WalletCommand::GetNewAddress { label, reply })
            .await
    }

    pub async fn send(&self, request: TransactionRequest) -> Result<TxId, RpcError> {
        self.dispatch(|reply| WalletCommand::Send { request, reply }).await
    }

    pub async fn unlock(&self) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::Unlock { reply }).await
    }

    pub async fn lock(&self) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::Lock { reply }).await
    }
}

/// The set of loaded wallets, addressable by name with a configured default.
pub struct WalletRegistry {
    wallets: HashMap<String, WalletHandle>,
    default: String,
}

impl WalletRegistry {
    pub fn new(default: String) -> Self {
        WalletRegistry { wallets: HashMap::new(), default }
    }

    pub fn insert(&mut self, handle: WalletHandle) {
        self.wallets.insert(handle.name.clone(), handle);
    }

    pub fn is_empty(&self) -> bool {
        self.wallets.is_empty()
    }

    /// Look up a wallet by name, or the default when `name` is `None`.
    pub fn get(&self, name: Option<&str>) -> Result<&WalletHandle, RpcError> {
        let name = name.unwrap_or(&self.default);
        self.wallets.get(name).ok_or_else(|| {
            RpcError::wallet_not_found(format!(
                "Requested wallet does not exist or is not loaded: {name}"
            ))
        })
    }

    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.wallets.keys().cloned().collect();
        v.sort();
        v
    }
}

/// Construct a handle from its parts (used by the actor's `spawn`).
pub(crate) fn make_handle(
    name: String,
    dir: PathBuf,
    network: Network,
    cmd_tx: mpsc::Sender<WalletCommand>,
    status_rx: watch::Receiver<SyncStatus>,
) -> WalletHandle {
    WalletHandle { name, dir, network, cmd_tx, status_rx }
}
