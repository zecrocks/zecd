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
use zcash_address::ZcashAddress;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::wallet::WalletTransparentOutput;
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::{ShieldedPool, TxId};
use zcash_transparent::address::TransparentAddress;
use zip32::DiversifierIndex;
use zip321::TransactionRequest;

use crate::coin::Coin;
use crate::config::SendPrivacy;
use crate::error::RpcError;
use crate::network::ZNetwork;
#[cfg(test)]
use crate::pools::Receiver;
use crate::pools::ReceiverSet;
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
#[non_exhaustive]
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
    /// Scan progress in `[0, 1]`: the height-based fraction of the wallet's scan range
    /// (birthday..chain tip) that `fully_scanned` has covered - NOT librustzcash's note-weighted
    /// ratio, which reads 1.0 from the start of a from-birthday restore (see
    /// `actor::scan_progress_ratio`). This is the *block scan* (compact-block) progress only; it
    /// reaches 1.0 when the scan catches up to the tip, which can be well before the wallet is
    /// ready to serve full history - see `pending_enhancements`.
    pub scan_progress: f64,
    /// True while the block scan lags the chain tip (`fully_scanned < chain_tip`, or either
    /// height still unknown).
    pub scanning: bool,
    /// Pending transaction-enhancement requests: the per-transaction full-tx fetches that backfill
    /// memos (and full transparent data) for transactions the wallet only ever saw as compact
    /// blocks. Counted as *distinct* requests (`actor::outstanding_requests` - upstream's
    /// spend-search generation emits duplicates quadratically on reused transparent addresses).
    /// Non-zero only once the block scan is caught up (it's `0` while `scanning`, where it
    /// would be unmeasured anyway). On a from-birthday restore this can be a multi-hour backlog
    /// that drains *after* `scan_progress` hits 1.0 and `scanning` goes false - so a wallet is only
    /// fully ready to serve history once this reaches `0`. It is not restore-only: the recurring
    /// transparent spend-search requests re-emit on every tip advance for a wallet holding
    /// unspent transparent UTXOs, so it transiently rises after sends/new blocks in steady state
    /// (which is what `readiness = "scanned"` exists for). Surfaced on `/status`, factored into
    /// `synced` readiness, and reflected in `getwalletinfo.scanning`.
    pub pending_enhancements: u64,
    /// The height through which the wallet is **fully enhanced**: every transaction mined at or
    /// below it has had its full data fetched, so its memos are readable. `None` means "not
    /// currently known" - never "everything is enhanced".
    ///
    /// This exists because zecd scans and enhances separately, which makes `fully_scanned` the
    /// wrong bound for anything reading memos. A scanned-but-unenhanced output is *present*
    /// with a NULL memo, so a consumer that treats "scanned" as "memos available" - or filters
    /// on `memo IS NOT NULL` and advances a cursor past what it saw - silently and permanently
    /// skips those outputs: they are already behind the cursor by the time enhancement fills
    /// them in. Clamping such a cursor to `enhanced_through` instead of `fully_scanned` makes
    /// that unrepresentable.
    ///
    /// It is a floor, not a promise about anything above it: heights above may be enhanced too.
    /// It is `None` while the block scan is running (the backlog is unmeasured there, see
    /// `pending_enhancements`), when the backlog is too large to resolve cheaply
    /// (`actor::ENHANCED_THROUGH_MAX_PROBE`), and on a database read error - all cases where a
    /// consumer should hold its cursor still rather than advance it. Surfaced on `/status`,
    /// `getwalletinfo.scanning`, and `waitforsync`.
    pub enhanced_through: Option<u32>,
    /// True when the wallet is passphrase-encrypted (Bitcoin Core's `HasEncryptionKeys()`).
    /// Drives whether `getwalletinfo` reports `unlocked_until` and how the passphrase RPCs behave.
    pub encrypted: bool,
    /// The account this wallet name resolves to inside its wallet database.
    ///
    /// A database can hold several accounts - that is how a fleet of watch-only wallets is
    /// scanned once rather than once each - so every read that reports this wallet's own money,
    /// history or addresses must be scoped to it ([`read::AccountScope`]). `None` while no
    /// account exists yet: an empty data directory whose account has not been rebuilt from
    /// `keys.toml`, e.g. an encrypted wallet awaiting its first `walletpassphrase`. Published on
    /// the status rather than fixed at spawn precisely so it appears when that bootstrap runs.
    pub account: Option<AccountUuid>,
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
    /// The block-scan matcher's current issuance frontier: `max(transparent_initial_scan,
    /// highest *exposed* external index + 1)`. Live coverage runs `transparent_gap_limit` past
    /// it. `None` until the matcher has been built (shielded-only wallets never build one).
    ///
    /// Surfaced so the two windows described in the project docs are observable rather than inferred:
    /// this one follows issuance, while the recovery horizon
    /// (`transparent_initial_scan + transparent_gap_limit`) follows funding and is what bounds a
    /// from-seed restore.
    pub transparent_frontier: Option<u32>,
    /// `transparent_initial_scan + transparent_gap_limit` - the bound a from-seed restore
    /// recovers within. Anchored on *funding*, so unlike `transparent_frontier` it does not move
    /// when addresses are merely issued. `None` for shielded-only wallets.
    pub transparent_recovery_horizon: Option<u32>,
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

/// What kind of receiving address `getnewaddress` (and `z_getaddressforaccount`) should derive.
/// Resolved at the RPC layer from the `address_type` / `receiver_types` argument and the wallet's
/// configured defaults; the actor is the authority that turns it into an actual address.
#[derive(Debug, Clone)]
pub enum ReceiverRequest {
    /// No per-call override: the wallet's configured default - a bare transparent address when
    /// the wallet's `transparent_default` is set, otherwise a Unified Address with the wallet's
    /// `default_receivers`.
    Default,
    /// An explicit shielded receiver set (already validated as a subset of the enabled pools).
    Shielded(ReceiverSet),
    /// A bare transparent (`t1…`/`tm…`) address. Only valid when the wallet enables transparent
    /// receiving (checked at the RPC layer and re-checked by the actor).
    Transparent,
}

/// One derived receiving address plus the derivation index it came from, as returned by
/// `z_getaddressforaccount`. The index is the shielded **diversifier index** for a Unified
/// Address and the BIP 44 **external child index** for a bare transparent address (which is why
/// it is reported at all: `getnewaddress` returns a bare string, so a caller reconciling its
/// issued transparent range against the chain otherwise has no way to learn which index it was
/// handed).
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    /// The encoded address (a Unified Address, or a bare `t1…`/`tm…` for a transparent request).
    pub address: String,
    /// The index the address was derived at (diversifier index, or transparent child index).
    pub index: u128,
    /// The receiver types actually derived, in the RPC's vocabulary: `sapling`/`orchard` for a
    /// UA, `p2pkh` for a bare transparent address. Echoed back so a caller that let the wallet's
    /// defaults decide (an omitted `receiver_types`) still learns what it got.
    pub receiver_types: Vec<&'static str>,
}

/// The funding source for a send - input-side coin control, resolved from `z_sendmany`'s
/// `fromaddress`. One source per send: transparent UTXOs and shielded notes are never mixed in
/// one transaction, so a shortfall on the named source is `-6` rather than a silent top-up from
/// the other pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SendSource {
    /// No source named (`sendtoaddress`/`sendmany`, which have no `fromaddress`): shielded notes
    /// fund the send. One legacy exception: under `AllowFullyTransparent` with all-transparent
    /// recipients, the fully-transparent t->t branch still engages (the pre-`SendSource`
    /// behaviour of the Bitcoin-dialect sends, pinned by the t2t regtests).
    ///
    /// The default: naming no source is what every send that has no `fromaddress` does.
    #[default]
    Unspecified,
    /// An explicitly shielded source (`z_sendmany` from a UA / shielded address): the account's
    /// shielded notes only - never transparent UTXOs, whatever the policy. Per-address shielded
    /// coin control is not supported (notes are account-scoped): the account is the source, and
    /// the address only names it.
    Shielded,
    /// Fund the send from the wallet's non-coinbase transparent UTXOs (`z_sendmany` from a
    /// wallet-owned t-address, or `ANY_TADDR`). `None` = any of the account's transparent
    /// receivers (`ANY_TADDR`); `Some(addr)` = only that address's UTXOs. Requires
    /// `AllowRevealedSenders` (or `AllowFullyTransparent`); with a shielded recipient this is
    /// the t->z shielding send (change shields either way, except on the t->t path).
    Transparent(Option<TransparentAddress>),
}

/// The source-address selector for `z_shieldcoinbase` (zcashd's `fromaddress` argument).
#[derive(Clone, Debug)]
pub enum ShieldCoinbaseFrom {
    /// zcashd's `"*"`: sweep coinbase UTXOs from every transparent receiver the wallet has
    /// exposed. Safe for zecd (one account per wallet), unlike a cross-account wildcard.
    AnyTaddr,
    /// A single wallet-owned transparent address.
    Address(TransparentAddress),
}

/// The synchronous half of `z_shieldcoinbase`: the built shielding proposal plus the pre-flight
/// selection stats zcashd reports in the RPC's immediate response (`shieldingUTXOs`,
/// `shieldingValue`, `remainingUTXOs`, `remainingValue` - the latter two being the mature
/// coinbase UTXOs left *un*selected by the proposal's `limit`/block-space cap). The proposal is
/// executed afterwards on a detached async operation, mirroring zcashd's flow: the selection is
/// fixed at call time, the proving/broadcast happens under the returned opid.
pub struct ShieldCoinbasePlan {
    /// The shielding proposal (`propose_shielding_coinbase`: coinbase-only inputs, a single
    /// shielded payment of `input_total - fee`, **no change in any pool**).
    pub proposal: Proposal<StandardFeeRule, std::convert::Infallible>,
    pub shielding_utxos: u64,
    /// Zatoshis selected for shielding (input total, before the fee).
    pub shielding_value: u64,
    pub remaining_utxos: u64,
    /// Zatoshis of mature coinbase UTXOs left unselected.
    pub remaining_value: u64,
}

/// The source selector for `z_mergetoaddress` (zcashd's `fromaddresses` argument), resolved at
/// the RPC layer. One source **class** per merge: transparent UTXOs and shielded notes are never
/// combined in one transaction (the same one-source-per-send invariant as [`SendSource`];
/// consolidating both takes two calls).
#[derive(Clone, Debug)]
pub enum MergeSource {
    /// Merge non-coinbase transparent UTXOs. `None` = `ANY_TADDR` (every wallet receiver);
    /// `Some(addrs)` = only the named wallet-owned addresses' UTXOs.
    Transparent(Option<Vec<TransparentAddress>>),
    /// Merge shielded notes from the given pools (`ANY_SAPLING` = `[Sapling]`, `ANY_ORCHARD` =
    /// `[Orchard, Ironwood]` - one family, since post-NU6.3 an Orchard receiver holds Ironwood
    /// notes; a wallet-owned shielded/UA address = the account's enabled pools, the address only
    /// naming the account as in `z_sendmany`).
    Shielded(Vec<ShieldedPool>),
}

/// The work a `z_mergetoaddress` proposal fixed at call time, executed later under the opid.
/// Selection happens in the synchronous half (like [`ShieldCoinbasePlan`]), so the RPC's
/// `merging*`/`remaining*` stats describe exactly what the operation will spend; a send racing
/// the opid fails cleanly at execute.
pub enum MergeWork {
    /// A transparent-inputs → one-shielded-payment proposal (t→z merge), executed via the fused
    /// path like `z_shieldcoinbase` (no change in any pool; payment = inputs - fee).
    UtxoProposal(Proposal<StandardFeeRule, std::convert::Infallible>),
    /// A shielded-notes → one-payment proposal (z→z / z→t merge), executed via the fused path
    /// (no change; payment = inputs - fee).
    NoteProposal(Proposal<StandardFeeRule, ReceivedNoteId>),
    /// A fully-transparent t→t merge: the fixed input set and single payout for the native
    /// transparent builder (no change output - the payout IS `inputs - fee`).
    TransparentTx {
        inputs: Vec<WalletTransparentOutput<AccountUuid>>,
        to: TransparentAddress,
        amount: zcash_protocol::value::Zatoshis,
        fee: zcash_protocol::value::Zatoshis,
    },
}

/// The synchronous half of `z_mergetoaddress`: the fixed work plus the selection stats zcashd
/// reports in the RPC's immediate response. `merging*` counts/values are the selected inputs
/// (value pre-fee, like `shieldingValue`); `remaining*` are the eligible-but-unselected ones a
/// follow-up call would merge. The inapplicable side is zero (a transparent-source merge has no
/// note stats and vice versa).
pub struct MergePlan {
    pub work: MergeWork,
    pub merging_utxos: u64,
    pub merging_transparent_value: u64,
    pub merging_notes: u64,
    pub merging_shielded_value: u64,
    pub remaining_utxos: u64,
    pub remaining_transparent_value: u64,
    pub remaining_notes: u64,
    pub remaining_shielded_value: u64,
}

/// Commands sent from RPC handlers to the per-wallet actor (the sole DB writer).
pub enum WalletCommand {
    GetNewAddress {
        /// The kind of address to derive (per-call override resolved against wallet config).
        request: ReceiverRequest,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    /// Derive an address for the wallet's (single) account, backing `z_getaddressforaccount`.
    /// `diversifier_index` selects an exact index (re-deriving the same address idempotently);
    /// `None` picks the next unused index, like `getnewaddress`. `request` is the already-parsed
    /// receiver selection - a shielded set (validated against the enabled pools), a bare
    /// transparent receiver, or `Default` for the wallet's configured default. Returns the
    /// encoded address, the index used, and the receivers actually derived.
    GetAddressForAccount {
        request: ReceiverRequest,
        diversifier_index: Option<DiversifierIndex>,
        reply: oneshot::Sender<Result<DerivedAddress, RpcError>>,
    },
    Send {
        request: TransactionRequest,
        /// Per-call confirmations override (`z_sendmany`'s `minconf`). `None` uses the
        /// wallet-wide policy; `Some` overrides note selection for this send only.
        confirmations: Option<ConfirmationsPolicy>,
        /// Privacy policy for this send; `FullPrivacy` is enforced on the built proposal
        /// (no transparent component, no cross-pool turnstile).
        privacy: SendPrivacy,
        /// Funding source (`z_sendmany`'s `fromaddress`): shielded notes, or transparent UTXOs
        /// (requires `privacy.allows_transparent_inputs()`, re-checked on the actor).
        source: SendSource,
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
    /// Ask the actor to run a sync pass now rather than waiting out `[sync] interval_secs`
    /// (`waitforsync`). The reply is sent as soon as the request is recorded - it acknowledges
    /// the nudge, not the pass, which runs on the actor's next loop iteration. Waiting for the
    /// *result* is the caller's job, by watching `SyncStatus`.
    SyncNow {
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Zeroize the in-memory seed and cancel any pending relock (`walletlock`).
    Lock {
        reply: oneshot::Sender<Result<(), RpcError>>,
    },
    /// Sign `message` with the private key of a transparent address the wallet owns
    /// (`signmessage`). Routed through the actor because it needs the seed (held by the actor's
    /// `SeedKeeper`): a locked wallet yields `-13`, a watch-only wallet `-4`, an unowned address
    /// `-4`. Returns the base64-encoded signature.
    SignMessage {
        address: TransparentAddress,
        message: String,
        reply: oneshot::Sender<Result<String, RpcError>>,
    },
    /// Build a `z_shieldcoinbase` proposal (coinbase-only inputs → one shielded payment, no
    /// change) and return it with the pre-flight selection stats. Fast (SQL + fee math); the
    /// synchronous half of the RPC. Requires an unlocked spending wallet, like a send.
    ProposeShieldCoinbase {
        from: ShieldCoinbaseFrom,
        to_address: ZcashAddress,
        memo: Option<MemoBytes>,
        /// Cap on the number of coinbase UTXOs to select (highest-value first); `None` selects
        /// as many as fit the block-space bound (zcashd's `limit = 0`).
        limit: Option<usize>,
        reply: oneshot::Sender<Result<ShieldCoinbasePlan, RpcError>>,
    },
    /// Prove, store, and broadcast a previously-built `z_shieldcoinbase` proposal (the async
    /// half, run under the operation's opid). Serializes with every other send on the actor, so
    /// the selected UTXOs can't be double-spent by a concurrent send.
    ExecuteShieldCoinbase {
        proposal: Box<Proposal<StandardFeeRule, std::convert::Infallible>>,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    },
    /// Build a `z_mergetoaddress` plan (selection + fee math, no proving) and return it with
    /// the merging/remaining stats. The fast synchronous half of the RPC; requires an unlocked
    /// spending wallet, like a send.
    ProposeMergeToAddress {
        source: MergeSource,
        to_address: ZcashAddress,
        memo: Option<MemoBytes>,
        /// Cap on transparent inputs to merge (`None` = unlimited by count; both are still
        /// bounded by the block-space cap). zcashd's `transparent_limit`, default 50.
        transparent_limit: Option<usize>,
        /// Cap on shielded notes to merge (`None` = unlimited by count). zcashd's
        /// `shielded_limit`, default 200; additionally clamped to `[spend]
        /// orchard_action_limit` for Orchard-family selections.
        shielded_limit: Option<usize>,
        /// The resolved privacy policy: the RPC layer gates the transparent-source cases, and
        /// the actor enforces `FullPrivacy`'s no-cross-pool rule on the built proposal (the
        /// input pools aren't known until then), exactly as for a send.
        privacy: SendPrivacy,
        reply: oneshot::Sender<Result<MergePlan, RpcError>>,
    },
    /// Prove (where applicable), store, and broadcast a previously-built `z_mergetoaddress`
    /// plan (the async half, run under the operation's opid). Serializes with every other send
    /// on the actor.
    ExecuteMergeToAddress {
        work: Box<MergeWork>,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    },
}

/// A clonable, `Send + Sync` handle to one wallet. RPC handlers use it to issue writer
/// commands (via the actor) and to read the published [`SyncStatus`]. Read-only queries are
/// served directly from short-lived connections (see [`read`]).
#[derive(Clone)]
pub struct WalletHandle {
    pub name: String,
    /// This wallet's **engine** directory (`<wallet dir>/<coin>/<engine>`) - what the read
    /// paths open, not the wallet directory `keys.toml` sits in. See [`crate::config::engine_dir`].
    pub engine_dir: PathBuf,
    pub network: ZNetwork,
    /// The wallet-wide confirmations policy (`[spend]` config; ZIP-315 3/10 by default),
    /// used wherever an RPC doesn't override depth with an explicit `minconf`.
    pub confirmations: ConfirmationsPolicy,
    /// Shielded pools enabled on this wallet - used to validate a `getnewaddress` per-call
    /// receiver override before dispatching it to the actor.
    pub enabled_pools: ReceiverSet,
    /// Receivers this wallet's Unified Addresses include by default (a subset of `enabled_pools`).
    pub default_receivers: ReceiverSet,
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

    /// The coin this handle serves. Constant by construction - a `WalletHandle` is the Zcash
    /// engine's handle - but written as a method so the codec call sites that need a [`Coin`]
    /// read as "this wallet's coin" rather than hard-coding the answer.
    pub fn coin(&self) -> Coin {
        Coin::Zcash
    }

    /// Which account in this wallet's database its reads apply to.
    ///
    /// [`read::AccountScope::Any`] until the account exists (a pending bootstrap), which is also
    /// exactly the pre-fleet behaviour - and identical to naming the account whenever the
    /// database holds only one, which is every non-fleet wallet.
    pub fn account_scope(&self) -> read::AccountScope {
        match self.status_rx.borrow().account {
            Some(account) => read::AccountScope::Only(account),
            None => read::AccountScope::Any,
        }
    }

    /// A private receiver on the actor's published [`SyncStatus`], for RPC handlers that must
    /// *wait* for the wallet's view of the chain to move rather than poll it (the `waitfor*`
    /// blockchain RPCs). The clone inherits this handle's seen-version, which is the channel's
    /// initial one - so mark the current value seen (`borrow_and_update`) before reading the
    /// state you are about to wait on, or the first `changed()` resolves on an update you have
    /// already accounted for.
    pub fn subscribe_status(&self) -> watch::Receiver<SyncStatus> {
        self.status_rx.clone()
    }

    /// Build a handle wired to a fixed [`SyncStatus`] for unit tests - no actor, no DB behind it.
    /// The command channel is inert (its receiver is dropped, so any `dispatch` would fail), and
    /// `engine_dir` is empty; only `status()`/`name`/`network` reads are meaningful. Used to exercise
    /// `/wallet/<name>` routing in RPC handlers that read solely from the published sync status.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str, network: ZNetwork, status: SyncStatus) -> Self {
        WalletHandle::for_test_publishing(name, network, status).0
    }

    /// [`WalletHandle::for_test`] plus the live sender, for tests that need to *publish* a new
    /// status to a handle (the `waitfor*` RPCs wake on exactly that). Holding the sender also
    /// keeps the channel open, so `subscribe_status().changed()` waits rather than erroring.
    #[cfg(test)]
    pub(crate) fn for_test_publishing(
        name: &str,
        network: ZNetwork,
        status: SyncStatus,
    ) -> (Self, watch::Sender<SyncStatus>) {
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        // The receiver keeps borrowing the seeded value after the sender drops (tokio watch
        // retains the last value), so the seeded status stays readable for the handle's life.
        let (status_tx, status_rx) = watch::channel(status);
        let handle = WalletHandle {
            name: name.to_string(),
            engine_dir: PathBuf::new(),
            network,
            confirmations: ConfirmationsPolicy::default(),
            enabled_pools: ReceiverSet::single(Receiver::Orchard),
            default_receivers: ReceiverSet::single(Receiver::Orchard),
            first_seen: Arc::new(Mutex::new(HashMap::new())),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: 20,
            // Inert test handle: no encrypted seed, so `walletlock` is a no-op (returns -15).
            seed: None,
            cmd_tx,
            status_rx,
        };
        (handle, status_tx)
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

    /// Ask the actor to start a sync pass immediately (see [`WalletCommand::SyncNow`]).
    /// Returns once the nudge is recorded, not once the pass completes.
    pub async fn sync_now(&self) -> Result<(), RpcError> {
        self.dispatch(|reply| WalletCommand::SyncNow { reply })
            .await
    }

    pub async fn get_new_address(&self, request: ReceiverRequest) -> Result<String, RpcError> {
        self.dispatch(|reply| WalletCommand::GetNewAddress { request, reply })
            .await
    }

    /// Derive an address for the wallet's single account (`z_getaddressforaccount`).
    /// `diversifier_index` selects an exact index; `None` picks the next unused one. A shielded
    /// `request` must already have been validated against the wallet's enabled pools by the
    /// caller, and a transparent one against the wallet's transparent capability.
    pub async fn get_address_for_account(
        &self,
        request: ReceiverRequest,
        diversifier_index: Option<DiversifierIndex>,
    ) -> Result<DerivedAddress, RpcError> {
        self.dispatch(|reply| WalletCommand::GetAddressForAccount {
            request,
            diversifier_index,
            reply,
        })
        .await
    }

    /// Build, prove, and broadcast a send. `confirmations` overrides the wallet-wide
    /// confirmations policy for this send's note selection (`z_sendmany`'s `minconf`); `None`
    /// uses the configured policy, as the synchronous `sendtoaddress`/`sendmany` do. `privacy`
    /// is the resolved send privacy policy (`FullPrivacy` enforced on the built proposal).
    /// `source` is the funding source resolved from `z_sendmany`'s `fromaddress`
    /// (`SendSource::Unspecified` for the Bitcoin-dialect sends, which have none).
    pub async fn send(
        &self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
        privacy: SendPrivacy,
        source: SendSource,
    ) -> Result<TxId, RpcError> {
        self.dispatch(|reply| WalletCommand::Send {
            request,
            confirmations,
            privacy,
            source,
            reply,
        })
        .await
    }

    /// Build a `z_shieldcoinbase` proposal + pre-flight stats (the RPC's synchronous half).
    pub async fn propose_shield_coinbase(
        &self,
        from: ShieldCoinbaseFrom,
        to_address: ZcashAddress,
        memo: Option<MemoBytes>,
        limit: Option<usize>,
    ) -> Result<ShieldCoinbasePlan, RpcError> {
        self.dispatch(|reply| WalletCommand::ProposeShieldCoinbase {
            from,
            to_address,
            memo,
            limit,
            reply,
        })
        .await
    }

    /// Prove, store, and broadcast a `z_shieldcoinbase` proposal (the async half).
    pub async fn execute_shield_coinbase(
        &self,
        proposal: Proposal<StandardFeeRule, std::convert::Infallible>,
    ) -> Result<TxId, RpcError> {
        self.dispatch(|reply| WalletCommand::ExecuteShieldCoinbase {
            proposal: Box::new(proposal),
            reply,
        })
        .await
    }

    /// Build a `z_mergetoaddress` plan + merging/remaining stats (the RPC's synchronous half).
    #[allow(clippy::too_many_arguments)]
    pub async fn propose_merge_to_address(
        &self,
        source: MergeSource,
        to_address: ZcashAddress,
        memo: Option<MemoBytes>,
        transparent_limit: Option<usize>,
        shielded_limit: Option<usize>,
        privacy: SendPrivacy,
    ) -> Result<MergePlan, RpcError> {
        self.dispatch(|reply| WalletCommand::ProposeMergeToAddress {
            source,
            to_address,
            memo,
            transparent_limit,
            shielded_limit,
            privacy,
            reply,
        })
        .await
    }

    /// Execute a `z_mergetoaddress` plan (the async half).
    pub async fn execute_merge_to_address(&self, work: MergeWork) -> Result<TxId, RpcError> {
        self.dispatch(|reply| WalletCommand::ExecuteMergeToAddress {
            work: Box::new(work),
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

    /// Sign `message` with the private key of the transparent `address` (which must belong to this
    /// wallet's account), returning the base64-encoded signature. See [`WalletCommand::SignMessage`].
    pub async fn sign_message(
        &self,
        address: TransparentAddress,
        message: String,
    ) -> Result<String, RpcError> {
        self.dispatch(|reply| WalletCommand::SignMessage {
            address,
            message,
            reply,
        })
        .await
    }
}

/// A loaded wallet, tagged with the kind of wallet it is.
///
/// The tag keeps the registry's storage independent of the handle type, so the librustzcash
/// half of the tree stays confined to `wallet/` instead of appearing in the registry's own
/// signatures. Built the way `chain::AnySource` is: an enum, not a trait object.
pub enum CoinWallet {
    /// A Zcash wallet, served by the librustzcash-backed actor.
    Zcash(WalletHandle),
}

impl CoinWallet {
    /// The coin this wallet serves.
    pub fn coin(&self) -> Coin {
        match self {
            CoinWallet::Zcash(_) => Coin::Zcash,
        }
    }

    /// The wallet's name, as `/wallet/<name>` addresses it.
    pub fn name(&self) -> &str {
        match self {
            CoinWallet::Zcash(handle) => &handle.name,
        }
    }
}

/// The set of loaded wallets, addressable by name with a configured default.
pub struct WalletRegistry {
    wallets: HashMap<String, CoinWallet>,
    default: String,
}

impl WalletRegistry {
    pub fn new(default: String) -> Self {
        WalletRegistry {
            wallets: HashMap::new(),
            default,
        }
    }

    pub fn insert(&mut self, wallet: CoinWallet) {
        self.wallets.insert(wallet.name().to_string(), wallet);
    }

    pub fn is_empty(&self) -> bool {
        self.wallets.is_empty()
    }

    /// Look up a wallet by name, or the default when `name` is `None`.
    ///
    /// Returns the handle directly, so all ~38 handler call sites read the same as before the
    /// registry grew its tag. The exhaustive match is deliberate: it resolves at one
    /// chokepoint, where an accessor returning an `Option` would conflate "no such wallet"
    /// with "a wallet that exists but is not the kind you asked for" - and the `-18` contract
    /// depends on telling those apart.
    pub fn get(&self, name: Option<&str>) -> Result<&WalletHandle, RpcError> {
        match self.get_coin(name)? {
            CoinWallet::Zcash(handle) => Ok(handle),
        }
    }

    /// Look up a wallet without resolving its engine - what the dispatch-time coin gate needs,
    /// since it must decide whether a method serves this wallet's coin before any handler runs.
    /// Same `-18` contract as [`WalletRegistry::get`].
    pub fn get_coin(&self, name: Option<&str>) -> Result<&CoinWallet, RpcError> {
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
    engine_dir: PathBuf,
    network: ZNetwork,
    confirmations: ConfirmationsPolicy,
    enabled_pools: ReceiverSet,
    default_receivers: ReceiverSet,
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
        engine_dir,
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

    use crate::pools::Receiver;

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
            ReceiverSet::single(Receiver::Orchard),
            ReceiverSet::single(Receiver::Orchard),
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
