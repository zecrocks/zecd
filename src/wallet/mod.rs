//! Wallet management: the single-writer actor, the clonable handle used by RPC handlers,
//! and the multiwallet registry.

pub mod actor;
pub mod binding;
pub mod keys;
pub mod open;
pub mod read;
pub mod store;

#[cfg(test)]
mod regtest_tests;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot, watch};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::TxId;
use zip32::DiversifierIndex;
use zip321::TransactionRequest;

use crate::config::SendPrivacy;
use crate::error::RpcError;
use crate::network::ZNetwork;
#[cfg(test)]
use crate::pools::Pool;
use crate::pools::PoolSet;
use crate::wallet::store::Passphrase;

/// Transient, in-memory first-seen wall-clock times for **unmined** wallet transactions, keyed
/// by display-hex txid. zecd is stateless - this is never persisted (it is rebuilt naturally as
/// the mempool stream re-observes pending txs, and lost on restart, exactly like the async-op
/// registry). It exists only because an unmined tx has no on-chain time yet: the actor stamps the
/// clock when it first stores a tx from the mempool stream, and the history RPCs surface it as
/// `time`/`timereceived` (Bitcoin Core's `nTimeReceived`) until a block time supersedes it. The
/// actor prunes entries once their tx mines, so the map stays bounded by the unmined set.
pub type FirstSeen = Arc<Mutex<HashMap<String, i64>>>;

/// Shared, independently-lockable custody of the decrypted seed (see [`keys::SeedKeeper`]).
/// The wallet actor is the seed's normal owner/writer, but `walletlock`'s fast path locks this
/// directly from the [`WalletHandle`] - bypassing the actor's serialized command queue - so the
/// seed can be zeroized promptly even while the actor is blocked proving a long send. `Arc<Mutex>`
/// mirrors [`FirstSeen`]; the guarded operations are trivial and never `.await` while held.
pub type SharedSeed = Arc<Mutex<keys::SeedKeeper>>;

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
    /// The zebra endpoint, e.g. `"zebra-rpc 127.0.0.1:18234"`.
    pub server: Option<String>,
    pub conn_state: ConnState,
    pub chain_tip: Option<u32>,
    pub fully_scanned: Option<u32>,
    /// The wallet's birthday height (from `keys.toml`). Static for the life of the wallet;
    /// published on `SyncStatus` so the health server's "connected" readiness mode can
    /// sanity-check the upstream's tip against it without a DB read.
    pub birthday: Option<u32>,
    pub best_block_hash: Option<String>,
    /// Scan progress in `[0, 1]`. This is the *block scan* (compact-block) progress only; it
    /// reaches 1.0 when the scan catches up to the tip, which can be well before the wallet is
    /// ready to serve full history - see `pending_enhancements`.
    pub scan_progress: f64,
    pub scanning: bool,
    /// Pending transaction-enhancement requests: the per-transaction full-tx fetches that backfill
    /// memos (and full transparent data) for transactions the wallet only ever saw as compact
    /// blocks. Non-zero only once the block scan is caught up (it's `0` while `scanning`, where it
    /// would be unmeasured anyway). On a from-birthday restore this can be a multi-hour backlog
    /// that drains *after* `scan_progress` hits 1.0 and `scanning` goes false - so a wallet is only
    /// fully ready to serve history once this reaches `0`. Surfaced on `/status`, factored into
    /// `synced` readiness, and reflected in `getwalletinfo.scanning`.
    pub pending_enhancements: u64,
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
    /// Transparent initial-sync progress as `(exposed, target)`, when the wallet is
    /// pre-exposing (or has finished pre-exposing) `transparent_initial_scan` external addresses.
    /// `None` when the feature is off. Surfaced in `getwalletinfo.transparent.initial_sync` so an
    /// operator can poll the fill instead of grepping logs. Transient (rebuilt on restart).
    pub transparent_preexpose: Option<(u32, u32)>,
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

/// What kind of receiving address `getnewaddress` should derive. Resolved at the RPC layer from
/// the `address_type` argument and the wallet's configured defaults; the actor is the authority
/// that turns it into an actual address.
#[derive(Debug, Clone)]
pub enum ReceiverRequest {
    /// No per-call override: the wallet's configured default - a bare transparent address when
    /// the wallet's `transparent_default` is set, otherwise a Unified Address with the wallet's
    /// `default_receivers`.
    Default,
    /// An explicit shielded receiver set (already validated as a subset of the enabled pools).
    Shielded(PoolSet),
    /// A bare transparent (`t1…`/`tm…`) address. Only valid when the wallet enables transparent
    /// receiving (checked at the RPC layer and re-checked by the actor).
    Transparent,
}

/// Commands sent from RPC handlers to the per-wallet actor (the sole DB writer).
pub enum WalletCommand {
    GetNewAddress {
        /// The kind of address to derive (per-call override resolved against wallet config).
        request: ReceiverRequest,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    /// Derive a Unified Address for the wallet's (single) account, backing `z_getaddressforaccount`.
    /// `diversifier_index` selects an exact index (re-deriving the same address idempotently);
    /// `None` picks the next unused index, like `getnewaddress`. `receivers` is the already-resolved,
    /// already-validated receiver set. Returns the encoded UA and the diversifier index used.
    GetAddressForAccount {
        receivers: PoolSet,
        diversifier_index: Option<DiversifierIndex>,
        reply: oneshot::Sender<Result<(String, u128), RpcError>>,
    },
    Send {
        request: TransactionRequest,
        /// Per-call confirmations override (`z_sendmany`'s `minconf`). `None` uses the
        /// wallet-wide policy; `Some` overrides note selection for this send only.
        confirmations: Option<ConfirmationsPolicy>,
        /// Privacy policy for this send; `FullPrivacy` is enforced on the built proposal
        /// (no transparent component, no cross-pool turnstile).
        privacy: SendPrivacy,
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
    /// Shielded pools enabled on this wallet - used to validate a `getnewaddress` per-call
    /// receiver override before dispatching it to the actor.
    pub enabled_pools: PoolSet,
    /// Receivers this wallet's Unified Addresses include by default (a subset of `enabled_pools`).
    pub default_receivers: PoolSet,
    /// Whether this wallet may hand out bare transparent receiving addresses - gates a
    /// `getnewaddress "" "transparent"` request (`-8` when off).
    pub transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` returns a bare transparent address.
    pub transparent_default: bool,
    /// This wallet's external transparent gap limit - the stateless-restore scan depth, surfaced
    /// in `getwalletinfo` so an operator can audit transparent coverage.
    pub transparent_gap_limit: u32,
    /// Transient first-seen times for unmined txs, shared with the actor (the writer). See
    /// [`FirstSeen`].
    first_seen: FirstSeen,
    /// The shared seed, present only for a passphrase-encrypted wallet - the only kind
    /// `walletlock` can lock. `Some` enables the fast path in [`WalletHandle::lock`]; `None`
    /// (unencrypted/watch-only) makes it a no-op so the actor returns the usual `-15`.
    seed: Option<SharedSeed>,
    cmd_tx: mpsc::Sender<WalletCommand>,
    status_rx: watch::Receiver<SyncStatus>,
}

impl WalletHandle {
    pub fn status(&self) -> SyncStatus {
        self.status_rx.borrow().clone()
    }

    /// Build a handle wired to a fixed [`SyncStatus`] for unit tests - no actor, no DB behind it.
    /// The command channel is inert (its receiver is dropped, so any `dispatch` would fail), and
    /// `dir` is empty; only `status()`/`name`/`network` reads are meaningful. Used to exercise
    /// `/wallet/<name>` routing in RPC handlers that read solely from the published sync status.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str, network: ZNetwork, status: SyncStatus) -> Self {
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        // The receiver keeps borrowing the seeded value after the sender drops (tokio watch
        // retains the last value), so the seeded status stays readable for the handle's life.
        let (_status_tx, status_rx) = watch::channel(status);
        WalletHandle {
            name: name.to_string(),
            dir: PathBuf::new(),
            network,
            confirmations: ConfirmationsPolicy::default(),
            enabled_pools: PoolSet::single(Pool::Orchard),
            default_receivers: PoolSet::single(Pool::Orchard),
            first_seen: Arc::new(Mutex::new(HashMap::new())),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: 20,
            // Inert test handle: no encrypted seed, so `walletlock` is a no-op (returns -15).
            seed: None,
            cmd_tx,
            status_rx,
        }
    }

    /// Snapshot of the transient first-seen times for unmined txs (display-hex txid → unix time),
    /// for joining into history responses. Empty after a restart until the mempool stream
    /// re-observes still-pending txs (zecd is stateless; these times are never persisted).
    pub fn first_seen(&self) -> HashMap<String, i64> {
        self.first_seen
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// The transient first-seen time of one transaction, if the actor has observed it unmined.
    pub fn first_seen_of(&self, txid_hex: &str) -> Option<i64> {
        self.first_seen.lock().ok()?.get(txid_hex).copied()
    }

    /// Whether the wallet actor task is still running. Becomes false once the actor stops -
    /// e.g. it panicked outside the per-command guard, or shut down - which lets the health
    /// endpoint surface a wallet whose *writes* are dead even though reads (which bypass the
    /// actor) still work.
    pub fn actor_alive(&self) -> bool {
        !self.cmd_tx.is_closed()
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

    pub async fn get_new_address(&self, request: ReceiverRequest) -> Result<String, RpcError> {
        self.dispatch(|reply| WalletCommand::GetNewAddress { request, reply })
            .await
    }

    /// Derive a Unified Address for the wallet's single account (`z_getaddressforaccount`).
    /// `diversifier_index` selects an exact index; `None` picks the next unused one. `receivers`
    /// must already have been validated against the wallet's enabled pools by the caller.
    pub async fn get_address_for_account(
        &self,
        receivers: PoolSet,
        diversifier_index: Option<DiversifierIndex>,
    ) -> Result<(String, u128), RpcError> {
        self.dispatch(|reply| WalletCommand::GetAddressForAccount {
            receivers,
            diversifier_index,
            reply,
        })
        .await
    }

    /// Build, prove, and broadcast a send. `confirmations` overrides the wallet-wide
    /// confirmations policy for this send's note selection (`z_sendmany`'s `minconf`); `None`
    /// uses the configured policy, as the synchronous `sendtoaddress`/`sendmany` do. `privacy`
    /// is the resolved send privacy policy (`FullPrivacy` enforced on the built proposal).
    pub async fn send(
        &self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
        privacy: SendPrivacy,
    ) -> Result<TxId, RpcError> {
        self.dispatch(|reply| WalletCommand::Send {
            request,
            confirmations,
            privacy,
            reply,
        })
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

    /// `walletlock`: drop the decrypted seed.
    ///
    /// Fast path (belt-and-suspenders): the wallet actor processes one command at a time, so a
    /// `Lock` queued behind a send that is mid-proof would otherwise wait out the whole proving
    /// window before the seed is zeroized - leaving the decrypted seed resident far longer than
    /// the operator intended. For an encrypted wallet, zeroize the in-memory seed *immediately*,
    /// without waiting for the actor's queue. The in-flight send already derived its spending key
    /// into a local before proving, so this can't disturb it; any *queued* send then fails `-13`
    /// (unlock needed) when it reaches key derivation, which is the correct post-lock behavior.
    ///
    /// The actor still runs the `Lock` command below: it is the single writer of the relock
    /// deadline and the published status, and it returns the authoritative result (notably `-15`
    /// for an unencrypted wallet, which carries no `seed` here and so skips the fast path).
    /// [`keys::SeedKeeper::lock`] is idempotent, so the actor re-locking an already-locked seed is
    /// a harmless no-op.
    pub async fn lock(&self) -> Result<(), RpcError> {
        if let Some(seed) = &self.seed {
            // Recover from a poisoned mutex (a panic while a guard was held): a locked-out seed
            // that can never be zeroized would be strictly worse than proceeding.
            seed.lock().unwrap_or_else(|p| p.into_inner()).lock();
        }
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_handle(
    name: String,
    dir: PathBuf,
    network: ZNetwork,
    confirmations: ConfirmationsPolicy,
    enabled_pools: PoolSet,
    default_receivers: PoolSet,
    transparent_enabled: bool,
    transparent_default: bool,
    transparent_gap_limit: u32,
    first_seen: FirstSeen,
    seed: Option<SharedSeed>,
    cmd_tx: mpsc::Sender<WalletCommand>,
    status_rx: watch::Receiver<SyncStatus>,
) -> WalletHandle {
    WalletHandle {
        name,
        dir,
        network,
        confirmations,
        enabled_pools,
        default_receivers,
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
        first_seen,
        seed,
        cmd_tx,
        status_rx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use secrecy::SecretVec;

    use crate::pools::Pool;

    fn handle_with_seed(seed: Option<SharedSeed>) -> (WalletHandle, mpsc::Receiver<WalletCommand>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        // The sender is dropped here; a watch receiver still reads the last value after that, and
        // these tests never call `status()` anyway.
        let (_status_tx, status_rx) = watch::channel(SyncStatus::default());
        let handle = make_handle(
            "t".into(),
            PathBuf::from("/nonexistent"),
            crate::network::regtest(),
            ConfirmationsPolicy::default(),
            PoolSet::single(Pool::Orchard),
            PoolSet::single(Pool::Orchard),
            false,
            false,
            20,
            Arc::new(Mutex::new(HashMap::new())),
            seed,
            cmd_tx,
            status_rx,
        );
        (handle, cmd_rx)
    }

    /// `walletlock`'s fast path must zeroize the seed *immediately*, before the actor drains its
    /// command queue - this is the whole point: an operator can lock a wallet whose actor is
    /// blocked proving a long send. We stand in for a mid-proof actor with one that receives the
    /// `Lock` command but delays its reply, and assert the shared seed is already gone while the
    /// `lock()` call is still waiting on that reply.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn walletlock_fast_path_zeroizes_seed_before_actor_replies() {
        let shared: SharedSeed = Arc::new(Mutex::new(keys::SeedKeeper::unlocked(SecretVec::new(
            vec![7u8; 32],
        ))));
        let (handle, mut cmd_rx) = handle_with_seed(Some(shared.clone()));
        assert!(shared.lock().unwrap().is_unlocked());

        // A deliberately slow "busy actor": it accepts the Lock but replies only after a delay,
        // the way an actor stuck in `block_in_place` proving would.
        let actor = tokio::spawn(async move {
            match cmd_rx.recv().await {
                Some(WalletCommand::Lock { reply }) => {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = reply.send(Ok(()));
                }
                _ => panic!("expected a Lock command"),
            }
        });

        let lock_call = tokio::spawn(async move { handle.lock().await });

        // Well within the actor's 300ms reply delay: the fast path should already have zeroized
        // the seed even though `lock()` has not returned yet.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !shared.lock().unwrap().is_unlocked(),
            "fast path must zeroize the seed before the busy actor replies"
        );
        assert!(
            !lock_call.is_finished(),
            "lock() should still be awaiting the actor"
        );

        // And once the actor finally drains the command, the call completes successfully.
        lock_call.await.unwrap().unwrap();
        actor.await.unwrap();
    }

    /// A handle with no shared seed (an unencrypted or watch-only wallet) has no fast path: it
    /// simply forwards `Lock` to the actor, which is the authority on the `-15`/`-4` result.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn walletlock_without_shared_seed_defers_to_actor() {
        let (handle, mut cmd_rx) = handle_with_seed(None);
        let actor = tokio::spawn(async move {
            match cmd_rx.recv().await {
                Some(WalletCommand::Lock { reply }) => {
                    let _ = reply.send(Err(RpcError::misc("from actor")));
                }
                _ => panic!("expected Lock"),
            }
        });
        let err = handle.lock().await.unwrap_err();
        assert_eq!(err.message, "from actor");
        actor.await.unwrap();
    }
}
