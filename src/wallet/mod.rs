//! Wallet management: the single-writer actor, the clonable handle used by RPC handlers,
//! and the multiwallet registry.

pub mod actor;
pub mod keys;
pub mod labels;
pub mod open;
pub mod read;
pub mod store;

#[cfg(test)]
mod regtest_tests;

use std::collections::HashMap;
use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot, watch};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::TxId;
use zip321::TransactionRequest;

use crate::error::RpcError;
use crate::network::ZNetwork;
use crate::wallet::store::Passphrase;

/// Connection state to lightwalletd, surfaced for monitoring (e.g. to distinguish "all
/// upstreams down" from "still syncing" on `/readyz`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnState {
    /// No usable client: every configured upstream is currently unreachable.
    #[default]
    Down,
    /// Connected and scanning toward the chain tip.
    Syncing,
    /// Connected and fully caught up.
    Ready,
}

impl ConnState {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnState::Down => "down",
            ConnState::Syncing => "syncing",
            ConnState::Ready => "ready",
        }
    }
}

/// A snapshot of sync state, published by the actor and read by blockchain/wallet RPCs.
#[derive(Clone, Debug, Default)]
pub struct SyncStatus {
    pub connected: bool,
    /// Active lightwalletd endpoint, e.g. `"zec.rocks:443 (tls=true)"`.
    pub server: Option<String>,
    pub conn_state: ConnState,
    pub chain_tip: Option<u32>,
    pub fully_scanned: Option<u32>,
    pub best_block_hash: Option<String>,
    /// Scan progress in `[0, 1]`.
    pub scan_progress: f64,
    pub scanning: bool,
    /// True when the wallet is passphrase-encrypted (Bitcoin Core's `HasEncryptionKeys()`).
    /// Drives whether `getwalletinfo` reports `unlocked_until` and how the passphrase RPCs behave.
    pub encrypted: bool,
    /// True for a watch-only wallet (imported UFVK; no spending material anywhere). Drives
    /// `getwalletinfo.private_keys_enabled` - the wallet-level signal, as in Bitcoin Core's
    /// descriptor wallets (per-address `iswatchonly` is deprecated there and stays false).
    pub watch_only: bool,
    /// For an encrypted wallet: the unix time the seed auto-relocks (0 = locked now), matching
    /// Bitcoin Core's `getwalletinfo.unlocked_until`. `None` for unencrypted wallets.
    pub unlocked_until: Option<i64>,
    /// Display-hex txid of the most recent auto-shield transaction this process created
    /// (tparty only; surfaced by `getshieldinginfo`).
    pub last_shield_txid: Option<String>,
}

impl SyncStatus {
    /// Confirmations for a transaction mined at `mined_height`, anchored to the wallet's
    /// fully-scanned height - the same height `getblockcount` reports - so the classic
    /// client computation `getblockcount() - tx.blockheight + 1` agrees with this field.
    /// (Anchoring to `chain_tip` instead made the two disagree whenever scanning lagged.)
    pub fn confirmations(&self, mined_height: Option<u32>) -> i64 {
        match (self.fully_scanned, mined_height) {
            (Some(scanned), Some(h)) if scanned >= h => (scanned - h + 1) as i64,
            _ => 0,
        }
    }
}

/// Raw transaction bytes plus the mined height reported by lightwalletd (when the tx was
/// fetched remotely; `None` for unmined txs and for locally-stored copies, whose height the
/// caller already knows from the wallet DB).
#[derive(Clone, Debug)]
pub struct RawTx {
    pub data: Vec<u8>,
    pub mined_height: Option<u32>,
}

/// Commands sent from RPC handlers to the per-wallet actor (the sole DB writer).
pub enum WalletCommand {
    GetNewAddress {
        label: Option<String>,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    /// Derive the next transparent (P2PKH) deposit address (tparty's `getnewaddress`).
    GetNewTransparentAddress {
        label: Option<String>,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    /// Immediately attempt to shield all spendable transparent funds, ignoring the
    /// configured threshold (tparty's `shieldfunds`). Replies with the shielding txid, or
    /// `None` when there was nothing spendable to shield.
    ShieldNow {
        reply: oneshot::Sender<Result<Option<TxId>, RpcError>>,
    },
    Send {
        request: TransactionRequest,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    },
    /// Fetch the raw bytes of a transaction (from the wallet, else lightwalletd).
    GetRawTx {
        txid: TxId,
        reply: oneshot::Sender<Result<Option<RawTx>, RpcError>>,
    },
    /// Broadcast caller-supplied raw transaction bytes (for `sendrawtransaction`).
    Broadcast {
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Unlock an encrypted wallet for `timeout_secs` (Bitcoin Core's `walletpassphrase`):
    /// decrypt the seed with `passphrase`, hold it, and auto-relock after the timeout.
    Unlock {
        passphrase: Passphrase,
        timeout_secs: i64,
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Zeroize the in-memory seed and cancel any pending relock (`walletlock`).
    Lock {
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Encrypt a previously-unencrypted wallet with `passphrase` (`encryptwallet`): re-wrap the
    /// mnemonic under scrypt and leave the wallet locked.
    EncryptWallet {
        passphrase: Passphrase,
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Change an encrypted wallet's passphrase (`walletpassphrasechange`).
    ChangePassphrase {
        old: Passphrase,
        new: Passphrase,
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
    pub network: ZNetwork,
    /// The wallet-wide confirmations policy (`[spend]` config; ZIP-315 3/10 by default),
    /// used wherever an RPC doesn't override depth with an explicit `minconf`.
    pub confirmations: ConfirmationsPolicy,
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

    pub async fn get_new_transparent_address(
        &self,
        label: Option<String>,
    ) -> Result<String, RpcError> {
        self.dispatch(|reply| WalletCommand::GetNewTransparentAddress { label, reply })
            .await
    }

    pub async fn shield_now(&self) -> Result<Option<TxId>, RpcError> {
        self.dispatch(|reply| WalletCommand::ShieldNow { reply })
            .await
    }

    pub async fn send(&self, request: TransactionRequest) -> Result<TxId, RpcError> {
        self.dispatch(|reply| WalletCommand::Send { request, reply })
            .await
    }

    pub async fn get_raw_tx(&self, txid: TxId) -> Result<Option<RawTx>, RpcError> {
        self.dispatch(|reply| WalletCommand::GetRawTx { txid, reply })
            .await
    }

    pub async fn broadcast(&self, data: Vec<u8>) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::Broadcast { data, reply })
            .await
    }

    pub async fn unlock(&self, passphrase: Passphrase, timeout_secs: i64) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::Unlock {
            passphrase,
            timeout_secs,
            reply,
        })
        .await
    }

    pub async fn lock(&self) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::Lock { reply }).await
    }

    pub async fn encrypt_wallet(&self, passphrase: Passphrase) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::EncryptWallet { passphrase, reply })
            .await
    }

    pub async fn change_passphrase(
        &self,
        old: Passphrase,
        new: Passphrase,
    ) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::ChangePassphrase { old, new, reply })
            .await
    }
}

/// The set of loaded wallets, addressable by name with a configured default.
pub struct WalletRegistry {
    wallets: HashMap<String, WalletHandle>,
    default: String,
}

impl WalletRegistry {
    pub fn new(default: String) -> Self {
        WalletRegistry {
            wallets: HashMap::new(),
            default,
        }
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
    network: ZNetwork,
    confirmations: ConfirmationsPolicy,
    cmd_tx: mpsc::Sender<WalletCommand>,
    status_rx: watch::Receiver<SyncStatus>,
) -> WalletHandle {
    WalletHandle {
        name,
        dir,
        network,
        confirmations,
        cmd_tx,
        status_rx,
    }
}
