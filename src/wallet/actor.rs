//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::collections::{HashSet, VecDeque};
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
    Account, AccountBirthday, AccountPurpose, AccountSource, InputSource, SentTransaction,
    SentTransactionOutput, TransactionDataRequest, TransactionStatus, TransparentOutputFilter,
    WalletRead, WalletUtxo, WalletWrite,
};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
};
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::proto::service;
use zcash_client_backend::wallet::{OvkPolicy, Recipient, TransparentAddressSource};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::{AccountUuid, FsBlockDb};
use zcash_keys::address::Address;
use zcash_primitives::transaction::builder::{BuildConfig, Builder};
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_primitives::transaction::Transaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedProtocol, TxId};
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
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
use crate::wallet::binding;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::read;
use crate::wallet::{
    make_handle, store, ConnState, FirstSeen, RawTx, ReceiverRequest, SharedSeed, SyncStatus,
    WalletCommand, WalletHandle,
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

/// How many transparent external addresses to derive per initial-sync chunk. Pre-exposure
/// is incremental: `sync_step` exposes one chunk per pass (before the block scan) and the actor
/// services queued RPC commands between chunks, so a deep `transparent_initial_scan` fills the
/// window without freezing the daemon in one uninterrupted synchronous burst. Sized so a single
/// chunk's synchronous derivation stays well under a second on typical disks (the actor can't
/// service a queued command mid-chunk), keeping worst-case RPC latency low without paying
/// per-chunk loop overhead on every index.
const TRANSPARENT_PREEXPOSE_CHUNK: u32 = 1_000;

/// How often to emit a transparent initial-sync progress heartbeat (throttled by wall time, not
/// by row - a deep scan must never log per address).
const PREEXPOSE_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Progress of the transparent initial sync (`transparent_initial_scan` pre-exposure) for the
/// current process. Transient - rebuilt on restart from the highest already-exposed index, like
/// the rest of sync progress (no statelessness break). Surfaced on [`SyncStatus`] and logged as a
/// time-throttled heartbeat.
struct PreexposeProgress {
    /// External indices exposed so far (also the next chunk's start index within this run).
    done: u32,
    /// Target depth (= `transparent_initial_scan`).
    total: u32,
    /// When this run began (for the completion-time and ETA lines).
    started: Instant,
    /// Last heartbeat time (throttle clock).
    last_log: Instant,
    /// `done` at the last heartbeat, so the rate is a short rolling window (not a drifting
    /// cumulative average).
    last_log_count: u32,
}

/// Pure progress math for the transparent initial-sync heartbeat: given the running count
/// (`done`), the `total` target, how many addresses were exposed in the last window (`did`), and
/// that window's length in seconds (`window`), return `(percent, addr_per_sec, eta_string)`. The
/// rate is a rolling window (not a cumulative average) so it tracks the current speed; both the
/// rate and ETA divides are guarded so a zero-length window or a stalled rate can't produce
/// `inf`/NaN (the ETA reads `"unknown"` instead). Extracted as a pure fn so it's unit-testable.
fn preexpose_progress_stats(done: u32, total: u32, did: u32, window: f64) -> (f64, f64, String) {
    let rate = if window > 0.0 {
        did as f64 / window
    } else {
        0.0
    };
    let pct = if total > 0 {
        (100.0 * done as f64 / total as f64).clamp(0.0, 100.0)
    } else {
        100.0
    };
    let remaining = total.saturating_sub(done);
    let eta = if rate > 0.0 {
        format!("~{:.0}s", remaining as f64 / rate)
    } else {
        "unknown".to_string()
    };
    (pct, rate, eta)
}

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
    /// Whether this wallet may hand out bare transparent receiving addresses.
    pub transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` returns a bare transparent address.
    pub transparent_default: bool,
    /// External transparent gap limit (restore scan depth). Applied to the wallet DB only when
    /// `transparent_enabled`.
    pub transparent_gap_limit: u32,
    /// Initial transparent scan depth: pre-expose external indices `0..N` on startup so the
    /// receive scan covers them, independent of the gap limit. `0` = off. Only used when
    /// `transparent_enabled`.
    pub transparent_initial_scan: u32,
    /// Whether `getnewaddress` may issue transparent addresses past the recovery window (warn-only);
    /// `false` fails the call with an actionable error instead. Only used when `transparent_enabled`.
    pub transparent_allow_beyond_recovery_window: bool,
    /// Warn when fewer than this many in-window transparent address slots remain. Only used when
    /// `transparent_enabled`.
    pub transparent_gap_warn_threshold: u32,
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
    /// Whether this wallet may hand out bare transparent receiving addresses.
    transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` returns a bare transparent address.
    transparent_default: bool,
    /// Initial transparent scan depth: pre-expose external indices `0..N` once so the receive
    /// scan covers them. `0` = off.
    transparent_initial_scan: u32,
    /// Whether `getnewaddress` may issue transparent addresses past the recovery window (warn-only);
    /// `false` fails the call with an actionable error instead.
    transparent_allow_beyond_recovery_window: bool,
    /// Warn when fewer than this many in-window transparent address slots remain before generation
    /// would hit the gap limit.
    transparent_gap_warn_threshold: u32,
    /// The wallet's exposed transparent receiving + change addresses, as a membership set for the
    /// block-scan / mempool receive matcher. Transient (rebuilt from the DB, respects the stateless
    /// invariant). librustzcash never asks us to scan our *receiving* transparent addresses for
    /// incoming funds (only to find spends of UTXOs we already hold), so zecd owns receive
    /// discovery: it matches each scanned block's (and each mempool tx's) transparent outputs
    /// against this set. Matching is O(outputs) with an O(1) membership test, independent of the
    /// set's size - what lets an exchange track ~100k addresses without per-address requests.
    /// `None` until first built; rebuilt lazily when `transparent_set_dirty`.
    transparent_scripts: Option<HashSet<TransparentAddress>>,
    /// Set when the exposed-address set may have grown (a recorded receive can extend the
    /// transparent gap, exposing new indices), so the next sync pass rebuilds `transparent_scripts`
    /// before matching. `transparent_preexposed` flips once `0..transparent_initial_scan` has been
    /// pre-exposed.
    transparent_set_dirty: bool,
    transparent_preexposed: bool,
    /// Live initial-sync progress while it runs (and the final state afterward), for the
    /// heartbeat log and the `getwalletinfo`/`/status` surfaces. `None` until the first chunk;
    /// stays `Some` once started so an operator can poll the completed count too.
    transparent_preexpose: Option<PreexposeProgress>,
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

    // Apply the configured external transparent gap limit only for transparent-enabled wallets, so
    // shielded-only wallets keep librustzcash's default and are completely unaffected.
    let db_data = open::init_dbs_with_gap_limit(
        cfg.network,
        &cfg.wallet_dir,
        cfg.transparent_enabled.then_some(cfg.transparent_gap_limit),
    )?;
    if cfg.transparent_enabled {
        // Surface the transparent receiving config for operator auditing of restore coverage:
        // a stateless rebuild rediscovers transparent funds only within `gap_limit` of the last
        // funded address.
        info!(
            "[{}] transparent receiving enabled (default_address={}, external_gap_limit={})",
            cfg.name, cfg.transparent_default, cfg.transparent_gap_limit
        );
    }
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

    // The selected account's UFVK (its canonical encoded form), for the binding checks below:
    // the database account must match keys.toml's pin, and an unlocked seed must derive it.
    // `None` only while a bootstrap is pending (no account yet); the bootstrap path runs the
    // same checks once it creates one.
    let account_ufvk = match account_id {
        Some(id) => Some(binding::account_ufvk_encoded(cfg.network, &db_data, id)?),
        None => None,
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
                        // Bind the decrypted seed to the account before trusting it: the seed
                        // must derive the account's UFVK, or keys.toml and the wallet database
                        // describe different wallets (a swapped database, or a swapped
                        // keys.toml + identity pair). Serving that would decrypt with keys the
                        // account's addresses do not belong to. Fatal, not a warning: this is
                        // the auto-unlock (unattended) wallet, so there is no later
                        // walletpassphrase where the mismatch could surface.
                        if let (Some(expected), Some(index)) =
                            (account_ufvk.as_deref(), account_index)
                        {
                            let derived = binding::seed_ufvk_encoded(cfg.network, &s, index)?;
                            if derived != expected {
                                return Err(anyhow::Error::new(binding::BindingMismatch(format!(
                                    "wallet '{}': the decrypted seed does not derive this \
                                         wallet's account; keys.toml and the wallet database \
                                         disagree (one of them was replaced or belongs to a \
                                         different wallet). Refusing to start.",
                                    cfg.name
                                ))));
                            }
                        }
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

    // Bind the database's account to keys.toml before serving anything: a match is required, a
    // mismatch is fatal (the database was swapped), and a missing pin (a keys.toml from before
    // the pin existed) is backfilled trust-on-first-use. Runs *after* the unlock chain above so
    // that when a seed is available the seed check has already vetoed a foreign account, and a
    // TOFU pin never blesses an account the seed disowns. (For a locked passphrase wallet the
    // TOFU pin is unverified until the first walletpassphrase, which runs the seed check and
    // refuses to unlock on a mismatch.)
    if let Some(ufvk) = account_ufvk.as_deref() {
        binding::verify_or_pin_account(&cfg.name, &cfg.keys_path, st.pinned_ufvk(), ufvk)?;
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
        transparent_enabled: cfg.transparent_enabled,
        transparent_default: cfg.transparent_default,
        transparent_initial_scan: cfg.transparent_initial_scan,
        transparent_allow_beyond_recovery_window: cfg.transparent_allow_beyond_recovery_window,
        transparent_gap_warn_threshold: cfg.transparent_gap_warn_threshold,
        transparent_scripts: None,
        transparent_set_dirty: true,
        transparent_preexposed: false,
        transparent_preexpose: None,
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
            cfg.transparent_enabled,
            cfg.transparent_default,
            cfg.transparent_gap_limit,
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

/// Pick a wallet-owned **internal** (change-scope) transparent address for change: the gap-start
/// (lowest unfunded) internal receiver among the account's exposed transparent receivers. Routing
/// change here (rather than to an external receive address) lets a from-seed restore recover it via
/// the internal gap chain and lets the history RPCs recognize it as change - distinct from a
/// deliberate self-send to an external address. Returns `None` if the wallet exposes no usable
/// internal receiver (the caller then falls back to a fresh external address).
fn pick_internal_change_address(db: &WriteDb, account: AccountUuid) -> Option<TransparentAddress> {
    use zcash_client_backend::wallet::Exposure;
    use zcash_transparent::keys::TransparentKeyScope;
    // `get_transparent_receivers(.., include_change = true, ..)` returns every internal address,
    // funded or not. An unfunded internal gap address (generated by gap advancement, never handed
    // out) has no recorded exposure height, so its exposure is `Unknown`; a funded change address
    // becomes `Exposed`. Pick the lowest-index **unfunded** (non-`Exposed`) internal address - the
    // gap frontier, i.e. the next change address - so change rotates without reuse and stays on the
    // internal gap chain (recoverable on a from-seed restore, recognized as change in history).
    let receivers = db.get_transparent_receivers(account, true, false).ok()?;
    receivers
        .into_iter()
        .filter(|(_, m)| m.scope() == Some(TransparentKeyScope::INTERNAL))
        .filter(|(_, m)| !matches!(m.exposure(), Exposure::Exposed { .. }))
        .filter_map(|(addr, m)| Some((m.address_index()?.index(), addr)))
        .min_by_key(|(idx, _)| *idx)
        .map(|(_, addr)| addr)
}

/// The serialized size of a transparent `TxOut` paying `addr`, matching what the `Builder` feeds
/// to the ZIP-317 fee rule: 8 bytes (value) + 1 byte (compact-size script length) + the
/// scriptPubKey (25 bytes P2PKH, 23 bytes P2SH). Used to compute the exact fee.
fn transparent_txout_size(addr: &TransparentAddress) -> usize {
    match addr {
        TransparentAddress::PublicKeyHash(_) => 8 + 1 + 25,
        TransparentAddress::ScriptHash(_) => 8 + 1 + 23,
    }
}

/// ZIP-317-aware greedy selection over `values_desc` (UTXO values, largest first) for a fully
/// transparent send. Returns `(num_selected, change, fee, has_change)`, or `None` if the inputs
/// cannot cover `recipients_total` plus the fee.
///
/// The fee is computed exactly as the transaction `Builder` does for a transaction whose inputs are
/// all standard P2PKH (which the wallet's received UTXOs always are, since `getnewaddress` only
/// hands out P2PKH receivers): the ZIP-317 logical action count is
/// `max(n_in, ceil(total_output_bytes / p2pkh_out_size))`, floored at `grace`, times `marginal`.
/// `recip_out_size` is the summed serialized size of the recipient outputs (so P2SH recipients are
/// priced correctly) and `change_out_size` is the size of the (P2PKH) change output. The `Builder`
/// requires the value balance to equal the fee *exactly*, so we either keep a transparent change
/// output sized to make that hold (`has_change`), or emit no change when an exact-cover transaction
/// balances at the lower no-change fee.
#[allow(clippy::too_many_arguments)]
fn select_transparent_inputs(
    values_desc: &[u64],
    recipients_total: u64,
    recip_out_size: usize,
    change_out_size: usize,
    p2pkh_out_size: usize,
    marginal: u64,
    grace: usize,
) -> Option<(usize, u64, u64, bool)> {
    // ZIP-317 output actions: ceil(total transparent output bytes / standard P2PKH output size).
    // Inputs are all standard P2PKH, so their action count is exactly `n_in`.
    let fee_for = |n_in: usize, out_bytes: usize| -> u64 {
        let out_actions = out_bytes.div_ceil(p2pkh_out_size);
        marginal * grace.max(n_in.max(out_actions)) as u64
    };
    let mut total: u64 = 0;
    for (i, v) in values_desc.iter().enumerate() {
        total += v;
        let n_in = i + 1;
        let fee_c = fee_for(n_in, recip_out_size + change_out_size);
        if total >= recipients_total + fee_c {
            let change = total - recipients_total - fee_c;
            if change > 0 {
                return Some((n_in, change, fee_c, true));
            }
            // change == 0: an exact no-change transaction may balance at the lower fee.
            let fee_n = fee_for(n_in, recip_out_size);
            if total == recipients_total + fee_n {
                return Some((n_in, 0, fee_n, false));
            }
            // change == 0 but the fees differ (a vanishingly rare large-tx case): adding another
            // input pushes the change above zero on the next pass.
        } else {
            // The "spend (almost) everything" case: no change, paying the exact fee.
            let fee_n = fee_for(n_in, recip_out_size);
            if total == recipients_total + fee_n {
                return Some((n_in, 0, fee_n, false));
            }
        }
    }
    None
}

/// If *every* payment in `request` targets a bare transparent (P2PKH/P2SH) address, return the
/// parsed `(address, amount)` recipients - the signal that `do_send` should take the
/// fully-transparent build path. Returns `Ok(None)` if any recipient has a shielded receiver (so
/// the caller falls back to the shielded proposal path), or if the request has no payments. A
/// payment missing an amount is `-8`.
fn transparent_only_recipients(
    net: &ZNetwork,
    request: &TransactionRequest,
) -> Result<Option<Vec<(TransparentAddress, Zatoshis)>>, RpcError> {
    use zcash_protocol::consensus::Parameters as _;
    let payments = request.payments();
    if payments.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(payments.len());
    for payment in payments.values() {
        let addr = payment
            .recipient_address()
            .clone()
            .convert_if_network::<Address>(net.network_type())
            .map_err(|e| RpcError::invalid_parameter(format!("invalid recipient address: {e}")))?;
        match addr {
            Address::Transparent(t) => {
                let amount = payment.amount().ok_or_else(|| {
                    RpcError::invalid_parameter("a send amount is required for each recipient")
                })?;
                out.push((t, amount));
            }
            // Any shielded (or unified, or TEX) recipient means this is not a fully transparent
            // send; fall back to the shielded proposal path.
            _ => return Ok(None),
        }
    }
    Ok(Some(out))
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

/// Extract the bare transparent receiver from a UA derived for a transparent-requiring request.
/// The request always requires a p2pkh receiver, so this is normally infallible; a `None` means
/// the account's viewing key unexpectedly lacks a transparent receiver.
fn transparent_receiver(
    ua: &zcash_keys::address::UnifiedAddress,
) -> Result<TransparentAddress, RpcError> {
    ua.transparent().copied().ok_or_else(|| {
        RpcError::wallet("derived address unexpectedly has no transparent receiver".to_string())
    })
}

/// In-window transparent address slots remaining before `getnewaddress` would hit the gap limit,
/// given an address at `gap_position` within a gap of size `gap_limit`. Matches librustzcash's
/// `GapMetadata::InGap` accounting: `gap_limit - (gap_position + 1)`.
fn gap_slots_remaining(gap_position: u32, gap_limit: u32) -> u32 {
    gap_limit.saturating_sub(gap_position.saturating_add(1))
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
                            // (Transparent receives are discovered by the block scan itself - see
                            // `sync_step` - and at 0-conf by the mempool path below; no separate
                            // per-address `getaddressutxos` pass is needed.)
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
            // `TransactionsInvolvingAddress` discovers transactions that receive or spend funds at
            // one of the wallet's transparent addresses. Compact blocks omit transparent I/O, so
            // mined transparent receives/spends are invisible to the block scan - this is the only
            // path that finds them. Query the upstream's address index for the requested range,
            // fetch+store each tx (filling in the transparent outputs), then record the address as
            // checked up to the range end so librustzcash stops re-requesting it.
            TransactionDataRequest::TransactionsInvolvingAddress(addr_req) => {
                use zcash_keys::encoding::AddressCodec as _;
                let address = addr_req.address().encode(&self.network);
                let chain_tip_u32 = u32::from(chain_tip);
                let start = u32::from(addr_req.block_range_start()).max(1);
                // librustzcash's `block_range_end` is exclusive; clamp the inclusive query/checked
                // height to the chain tip (or the tip itself when the request is open-ended).
                let as_of = match addr_req.block_range_end() {
                    Some(end_excl) => u32::from(end_excl).saturating_sub(1).min(chain_tip_u32),
                    None => chain_tip_u32,
                };
                if start <= as_of {
                    tracing::debug!(
                        "[{}] TIA: getaddresstxids addr={address} range={start}..={as_of}",
                        self.name
                    );
                    let txids = self
                        .fetch_transparent_txids(vec![address], start, as_of)
                        .await
                        .map_err(|e| anyhow!("{e}"))?;
                    tracing::debug!(
                        "[{}] TIA: getaddresstxids returned {} txid(s)",
                        self.name,
                        txids.len()
                    );
                    for txid in txids {
                        if let Some((tx, mined)) = self.fetch_full_tx(txid, chain_tip).await? {
                            decrypt_and_store_transaction(
                                &self.network,
                                &mut self.db_data,
                                &tx,
                                mined,
                            )?;
                        }
                    }
                }
                // Record the address as checked up to `as_of` (the inclusive end), whether or not
                // any txs were found, so the request converges instead of being re-emitted every
                // caught-up pass.
                self.db_data
                    .notify_address_checked(addr_req.clone(), BlockHeight::from_u32(as_of))?;
            }
        }
        Ok(())
    }

    /// Match a transaction's transparent outputs against the wallet's exposed transparent address
    /// set and record any that pay us as received UTXOs (`put_received_transparent_utxo`). Returns
    /// how many were recorded.
    ///
    /// This is the 0-conf half of transparent receive discovery: the block scan
    /// (`engine::sync_one_batch`) discovers *mined* transparent receives, and the mempool poller
    /// calls this with `height = None` so an incoming transparent payment is visible at 0 conf
    /// (`getunconfirmedbalance`/`listunspent minconf=0`), matching the shielded mempool path and
    /// bitcoind. librustzcash never discovers transparent *receives* itself - its
    /// `transaction_data_requests` only ask us to find *spends* of UTXOs we already hold - and
    /// `decrypt_and_store_transaction` records only shielded outputs, so zecd owns this.
    ///
    /// Matching is O(outputs-in-tx) with an O(1) set membership test, independent of how many
    /// addresses the wallet tracks. Sharing [`engine::owned_transparent_output`] with the block
    /// scan keeps the two discovery paths byte-for-byte consistent.
    fn record_tx_transparent_receives(
        &mut self,
        tx: &Transaction,
        height: Option<BlockHeight>,
    ) -> usize {
        if !self.transparent_enabled {
            return 0;
        }
        let h = height.map(u32::from);
        // Build the owned outputs while holding the (immutable) address-set borrow, then record
        // them with `&mut self.db_data` - keeping the two borrows from overlapping.
        let outputs: Vec<_> = {
            let Some(addresses) = self.transparent_scripts.as_ref() else {
                return 0;
            };
            let Some(bundle) = tx.transparent_bundle() else {
                return 0;
            };
            let txid = tx.txid();
            bundle
                .vout
                .iter()
                .enumerate()
                .filter_map(|(index, txout)| {
                    engine::owned_transparent_output(
                        addresses,
                        txid,
                        index as u32,
                        u64::from(txout.value()),
                        txout.script_pubkey().0 .0.clone(),
                        h,
                    )
                })
                .collect()
        };
        let mut recorded = 0;
        for output in outputs {
            match self.db_data.put_received_transparent_utxo(&output) {
                Ok(_) => recorded += 1,
                Err(e) => warn!(
                    "[{}] recording transparent receive {}:{} failed: {e}",
                    self.name,
                    output.outpoint().txid(),
                    output.outpoint().n(),
                ),
            }
        }
        if recorded > 0 {
            // A new receive may have extended the transparent gap; rebuild the set next pass.
            self.transparent_set_dirty = true;
        }
        recorded
    }

    /// Expose one chunk of external transparent indices `0..transparent_initial_scan` so the
    /// block scan covers them regardless of the (small) steady-state gap limit. Returns `true` while
    /// more indices remain, so the caller (`sync_step`) keeps cycling - servicing queued RPC commands
    /// between chunks - instead of freezing the actor for the whole derivation. Updates
    /// [`PreexposeProgress`] and emits the throttled heartbeat; logs the opening and completion lines
    /// once each. Resumable: within a run `progress.done` is the cursor, and the first chunk of a run
    /// recomputes the start from the highest already-exposed index (cheap restart). No-op (returns
    /// `false`) when the depth is 0 or already covered.
    fn preexpose_transparent_chunk(&mut self, account_id: AccountUuid) -> bool {
        let depth = self.transparent_initial_scan;
        if depth == 0 {
            return false;
        }
        let request = crate::pools::transparent_extraction_request();
        // Within a run, `progress.done` is the authoritative cursor; only the first chunk consults
        // the DB (to resume past whatever a surviving DB already exposed), so we don't re-query the
        // full receiver set on every chunk.
        let start = match self.transparent_preexpose.as_ref() {
            Some(p) => p.done,
            None => self.next_unexposed_external_index(account_id),
        };
        if start >= depth {
            // Already covered before we derived anything (e.g. a restart whose DB was complete).
            if self.transparent_preexpose.is_none() {
                info!(
                    "[{}] transparent initial sync already complete ({depth} addresses)",
                    self.name
                );
            }
            return false;
        }
        if self.transparent_preexpose.is_none() {
            let now = Instant::now();
            self.transparent_preexpose = Some(PreexposeProgress {
                done: start,
                total: depth,
                started: now,
                last_log: now,
                last_log_count: start,
            });
            if start > 0 {
                info!(
                    "[{}] resuming transparent initial sync at {start}/{depth} addresses",
                    self.name
                );
            } else {
                info!(
                    "[{}] starting transparent initial sync: {depth} addresses to scan",
                    self.name
                );
            }
        }
        let end = depth.min(start.saturating_add(TRANSPARENT_PREEXPOSE_CHUNK));
        for i in start..end {
            let div = DiversifierIndex::from(i);
            if let Err(e) = self.db_data.get_address_for_index(account_id, div, request) {
                warn!(
                    "[{}] transparent initial sync failed at index {i}: {e}",
                    self.name
                );
                // Stop attempting this process so we don't spin re-hitting the same index every
                // pass; the window is left partially exposed (recoverable on a later restart).
                return false;
            }
        }
        if let Some(p) = self.transparent_preexpose.as_mut() {
            p.done = end;
        }
        if end >= depth {
            let elapsed = self
                .transparent_preexpose
                .as_ref()
                .map(|p| p.started.elapsed().as_secs_f64())
                .unwrap_or(0.0);
            info!(
                "[{}] transparent initial sync complete: {depth} addresses in {elapsed:.0}s",
                self.name
            );
            return false;
        }
        self.maybe_log_preexpose_progress();
        true
    }

    /// The next external transparent index a restore would need to expose: one past the highest
    /// already-exposed external index (0 for a fresh/empty account). Used only for the first chunk
    /// of a run, to resume after a restart without re-deriving what the DB already has.
    fn next_unexposed_external_index(&self, account_id: AccountUuid) -> u32 {
        match self
            .db_data
            .get_transparent_receivers(account_id, false, false)
        {
            Ok(r) => r
                .values()
                .filter_map(|m| m.address_index())
                .map(|i| i.index().saturating_add(1))
                .max()
                .unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// Emit a transparent initial-sync progress heartbeat, throttled to one line per
    /// [`PREEXPOSE_LOG_INTERVAL`]. Rate is a short rolling window (addresses since the last line ÷
    /// wall time since it), so it tracks the current speed rather than a drifting average; the ETA
    /// is derived from that rate and flagged approximate. Monotonic `Instant` throughout, and the
    /// rate divide is guarded so a zero-length interval can't produce `inf`/NaN.
    fn maybe_log_preexpose_progress(&mut self) {
        let name = self.name.clone();
        let Some(p) = self.transparent_preexpose.as_mut() else {
            return;
        };
        let now = Instant::now();
        let window = now.saturating_duration_since(p.last_log).as_secs_f64();
        if window < PREEXPOSE_LOG_INTERVAL.as_secs_f64() {
            return;
        }
        let done = p.done;
        let total = p.total;
        let did = done.saturating_sub(p.last_log_count);
        let (pct, rate, eta) = preexpose_progress_stats(done, total, did, window);
        info!(
            "[{name}] transparent initial sync: {done}/{total} ({pct:.1}%), {rate:.0} addr/s, ETA {eta}"
        );
        p.last_log = now;
        p.last_log_count = done;
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
                // `decrypt_and_store_transaction` records only *shielded* outputs, so a transparent
                // receive needs zecd's own matcher: check this tx's transparent outputs against the
                // wallet's address set and record any that pay us as unmined (0-conf) UTXOs. This is
                // what makes an incoming transparent payment visible before its first confirmation
                // (`getunconfirmedbalance`/`listunspent minconf=0`), the same as the shielded path.
                let t_recorded = self.record_tx_transparent_receives(&tx, mined_height);

                // The tx is ours iff it now exists in the wallet DB - either the shielded
                // decrypt stored it or we just recorded a transparent receive from it.
                let txid_hex = txid.to_string();
                let ours = t_recorded > 0 || super::read::tx_exists(&self.wallet_dir, &txid_hex);
                tracing::debug!(
                    "[{}] processed mempool tx {txid} (ours={ours}, transparent_receives={t_recorded})",
                    self.name
                );
                // If the tx is ours and still unmined, stamp when we first saw it so
                // `gettransaction`/`listtransactions` can report `time`/`timereceived` (Bitcoin
                // Core's `nTimeReceived`) while it has no block time. This is held in memory only
                // - zecd is stateless, so it is never persisted (a restart/restore rebuilds it as
                // the mempool stream re-observes the tx, or it mines and the block time wins).
                if mined_height.is_none() && ours {
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
        let Some(account_id) = self.account_id else {
            return Ok(false);
        };

        // Transparent receive discovery rides on the block scan: the wallet's exposed transparent
        // addresses are matched against each scanned block's outputs (see `engine::sync_one_batch`).
        // Pre-expose the initial-scan window and (re)build the address set *before* the scan so
        // the historic range is matched against the full address set - including a from-seed
        // restore, where a high funded index is found only if `transparent_initial_scan` exposed it.
        if self.transparent_enabled {
            if !self.transparent_preexposed {
                // Derive the initial-scan window a chunk at a time. The window must be fully exposed before
                // the scan (so historical blocks are matched against every address), but a deep
                // `transparent_initial_scan` (~1180 addr/s) would freeze every actor-routed RPC for
                // minutes if done in one synchronous burst. So each pass exposes one chunk and, while
                // more remain, returns `worked = true` *without scanning*: the actor loop drains
                // queued commands between chunks and resumes here next pass, keeping the daemon live
                // (reads already bypass the actor; `/readyz` stays ready) while the window fills.
                let more = self.preexpose_transparent_chunk(account_id);
                // Newly-exposed indices must enter the match set before the scan reaches their blocks.
                self.transparent_set_dirty = true;
                if more {
                    self.update_status();
                    return Ok(true);
                }
                self.transparent_preexposed = true;
                // Startup audit: if the wallet already sits near/over the recovery window (e.g. many
                // addresses handed out ahead of funding, carried across a restart), warn once.
                self.audit_transparent_recovery_window(account_id);
            }
            if self.transparent_set_dirty {
                self.rebuild_transparent_set(account_id);
            }
        }

        let outcome = {
            let transparent = self.transparent_scripts.as_ref();
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
                transparent,
            )
            .await?
        };
        // A recorded receive may have extended the transparent gap (exposing new indices), so
        // rebuild the address set before the next pass to cover them.
        if outcome.transparent_recorded > 0 {
            self.transparent_set_dirty = true;
        }
        self.update_status();
        Ok(outcome.worked)
    }

    /// Rebuild [`Self::transparent_scripts`] from the account's exposed transparent receivers
    /// (external + internal/change). Cheap relative to a sync batch and only run when the set may
    /// have changed (`transparent_set_dirty`), so an exchange with ~100k addresses pays the query
    /// once per gap extension, not once per scanned block.
    fn rebuild_transparent_set(&mut self, account_id: AccountUuid) {
        match self
            .db_data
            .get_transparent_receivers(account_id, true, false)
        {
            Ok(receivers) => {
                let set: HashSet<TransparentAddress> = receivers.into_keys().collect();
                tracing::debug!(
                    "[{}] transparent address set rebuilt: {} exposed receiver(s)",
                    self.name,
                    set.len()
                );
                self.transparent_scripts = Some(set);
                self.transparent_set_dirty = false;
            }
            Err(e) => warn!("[{}] rebuilding transparent address set: {e}", self.name),
        }
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
                // Bind the rebuilt account to keys.toml's pin before adopting it (the same
                // startup check in `spawn`). The account was just derived from keys.toml's own
                // seed, so a mismatch means the pinned UFVK is inconsistent with that seed
                // (a tampered or foreign pin). Fail closed: leave the account unadopted (the
                // wallet serves no account) rather than serve under a pin the seed disowns.
                // The account row stays in the database, so the next daemon start surfaces
                // the same mismatch as a hard startup failure.
                match binding::account_ufvk_encoded(self.network, &self.db_data, id).and_then(
                    |ufvk| {
                        let pinned = store::WalletStore::read(&self.keys_path)?;
                        binding::verify_or_pin_account(
                            &self.name,
                            &self.keys_path,
                            pinned.pinned_ufvk(),
                            &ufvk,
                        )
                    },
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        error!(
                            "[{}] bootstrap: {e}. The rebuilt account is left unadopted; \
                             restarting the daemon will surface this as a startup failure.",
                            self.name
                        );
                        self.pending_bootstrap = None;
                        return;
                    }
                }
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
            transparent_preexpose: self
                .transparent_preexpose
                .as_ref()
                .map(|p| (p.done, p.total)),
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
            WalletCommand::GetNewAddress { request, reply } => {
                let res = self.get_new_address(request);
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

    fn get_new_address(&mut self, request: ReceiverRequest) -> Result<String, RpcError> {
        // Resolve the request against the wallet's configuration. `Default` becomes a bare
        // transparent address when the wallet defaults to transparent, else the configured
        // shielded `default_receivers`. The actor is the authority on the wallet's configuration,
        // so it re-validates an explicit shielded override and re-checks transparent enablement
        // (the RPC layer validates these too, before dispatch).
        let receivers = match request {
            ReceiverRequest::Transparent => return self.new_transparent_address(),
            ReceiverRequest::Default if self.transparent_default => {
                return self.new_transparent_address()
            }
            ReceiverRequest::Default => self.default_receivers.clone(),
            ReceiverRequest::Shielded(set) => {
                if !set.is_subset_of(&self.enabled_pools) {
                    return Err(RpcError::invalid_parameter(format!(
                        "requested receivers ({}) include a pool not enabled on this wallet ({})",
                        set.display_names(),
                        self.enabled_pools.display_names()
                    )));
                }
                set
            }
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

    /// Derive and persist a fresh bare transparent (`t1…`/`tm…`) receiving address for the
    /// account. ZIP-316 forbids a transparent-only Unified Address, so we derive a UA that
    /// requires both an Orchard and a transparent receiver (keys always derive all pools, so the
    /// Orchard receiver is always available), then extract and bare-encode the transparent
    /// receiver. Generating the UA persists `addresses.cached_transparent_receiver_address`, which
    /// is what lets the read paths and the receive-servicing loop recognise the address.
    fn new_transparent_address(&mut self) -> Result<String, RpcError> {
        if !self.transparent_enabled {
            return Err(RpcError::invalid_parameter(
                "transparent addresses are not enabled on this wallet \
                 (set [pools] transparent = true)",
            ));
        }
        let account_id = self.require_account()?;
        // Handing out a transparent receiver may expose a new address (notably the beyond-gap
        // issuance path, which exposes an index outside the current gap window): mark the matcher's
        // address set stale so the next sync pass rebuilds it and the block-scan / mempool matcher
        // recognizes a payment to the address we just issued. Within-window addresses are already in
        // the set (the gap window is pre-exposed), so this is only load-bearing past the window, but
        // it's cheap (one coalesced rebuild per sync pass) and keeps the set authoritative.
        self.transparent_set_dirty = true;
        let request = crate::pools::transparent_extraction_request();
        match self.db_data.get_next_available_address(account_id, request) {
            Ok(Some((ua, _))) => {
                let taddr = transparent_receiver(&ua)?;
                self.warn_if_gap_low(account_id, &taddr);
                use zcash_keys::encoding::AddressCodec as _;
                Ok(taddr.encode(&self.network))
            }
            Ok(None) => Err(RpcError::wallet(
                "no transparent address available for account; the account's viewing key may \
                 not support a transparent receiver"
                    .to_string(),
            )),
            // librustzcash fails closed once the recovery window (`gap_limit` consecutive unfunded
            // addresses) is full. With the operator's opt-in we issue past it anyway, warning that
            // such an address may be unrecoverable from seed; otherwise surface an actionable error.
            Err(SqliteClientError::ReachedGapLimit(..))
                if self.transparent_allow_beyond_recovery_window =>
            {
                self.new_transparent_address_beyond_gap(account_id)
            }
            Err(SqliteClientError::ReachedGapLimit(..)) => Err(RpcError::wallet(
                "transparent address gap limit reached: the recovery window is full of unfunded \
                 addresses, so no new address is recoverable from seed. Increase [pools] \
                 transparent_gap_limit and/or transparent_initial_scan, fund a lower-index \
                 address, or set transparent_allow_beyond_recovery_window = true to issue beyond \
                 the window anyway."
                    .to_string(),
            )),
            Err(e) => Err(RpcError::wallet(format!("address generation failed: {e}"))),
        }
    }

    /// Issue a transparent receiving address **beyond** the recovery window, used when
    /// `get_next_available_address` hit the gap limit and the operator has opted in via
    /// `transparent_allow_beyond_recovery_window`. librustzcash's gap reservation refuses such an
    /// address, so we expose the next sequential external index directly via `get_address_for_index`
    /// (the same primitive the initial sync uses). An address at an index a from-seed restore
    /// won't re-expose (i.e. `>= transparent_initial_scan`, with no nearby funding to extend the
    /// gap) may be unrecoverable, so it is warned about loudly.
    fn new_transparent_address_beyond_gap(
        &mut self,
        account_id: AccountUuid,
    ) -> Result<String, RpcError> {
        let next = self.next_external_transparent_index(account_id);
        let request = crate::pools::transparent_extraction_request();
        let div = DiversifierIndex::from(next);
        let ua = self
            .db_data
            .get_address_for_index(account_id, div, request)
            .map_err(map_address_for_index_error)?
            .ok_or_else(|| {
                RpcError::wallet(format!("Error: no address at diversifier index {next}."))
            })?;
        let taddr = transparent_receiver(&ua)?;
        // A restore re-exposes external indices `0..transparent_initial_scan`, so an index below
        // that floor stays recoverable even though it's past the steady-state generation gap.
        if next < self.transparent_initial_scan {
            info!(
                "[{}] issued transparent address at external index {next}, past the steady-state \
                 gap but still within transparent_initial_scan ({}) - recoverable from seed.",
                self.name, self.transparent_initial_scan
            );
        } else {
            warn!(
                "[{}] issued transparent address at external index {next}, OUTSIDE the \
                 stateless-restore recovery window. Funds received here may be UNRECOVERABLE from \
                 seed unless you raise [pools] transparent_gap_limit / transparent_initial_scan. \
                 (permitted by transparent_allow_beyond_recovery_window = true)",
                self.name
            );
        }
        use zcash_keys::encoding::AddressCodec as _;
        Ok(taddr.encode(&self.network))
    }

    /// The next external (non-change) transparent child index to hand out: one past the highest
    /// already-**exposed** external receiver (contiguous with what has been issued). Falls back to
    /// `0` if the wallet exposes none (it never reaches here in that case - the gap path would have
    /// an address available).
    fn next_external_transparent_index(&self, account_id: AccountUuid) -> u32 {
        use zcash_client_backend::wallet::Exposure;
        match self
            .db_data
            .get_transparent_receivers(account_id, false, false)
        {
            Ok(r) => r
                .values()
                .filter(|m| matches!(m.exposure(), Exposure::Exposed { .. }))
                .filter_map(|m| m.address_index())
                .map(|i| i.index().saturating_add(1))
                .max()
                .unwrap_or(0),
            Err(_) => 0,
        }
    }

    /// One-time startup check: warn if the wallet's transparent recovery window is already nearly
    /// exhausted (e.g. many addresses handed out ahead of funding and carried across a restart).
    /// Reuses [`Self::warn_if_gap_low`] over the highest-index exposed external receiver, which
    /// carries the current gap position. Never fatal - already-exposed addresses can't be un-issued.
    fn audit_transparent_recovery_window(&self, account_id: AccountUuid) {
        use zcash_client_backend::wallet::Exposure;
        let receivers = match self
            .db_data
            .get_transparent_receivers(account_id, false, false)
        {
            Ok(r) => r,
            Err(_) => return,
        };
        let highest = receivers
            .into_iter()
            .filter(|(_, m)| matches!(m.exposure(), Exposure::Exposed { .. }))
            .filter_map(|(addr, m)| Some((m.address_index()?.index(), addr)))
            .max_by_key(|(idx, _)| *idx);
        if let Some((_, taddr)) = highest {
            self.warn_if_gap_low(account_id, &taddr);
        }
    }

    /// Warn (best-effort) when a just-issued transparent address is among the last
    /// `transparent_gap_warn_threshold` recoverable slots before `getnewaddress` would hit the gap
    /// limit, so the operator can widen the window before addresses start landing outside it.
    fn warn_if_gap_low(&self, account_id: AccountUuid, taddr: &TransparentAddress) {
        use zcash_client_backend::wallet::{Exposure, GapMetadata};
        let meta = match self
            .db_data
            .get_transparent_address_metadata(account_id, taddr)
        {
            Ok(Some(m)) => m,
            _ => return,
        };
        if let Exposure::Exposed {
            gap_metadata:
                GapMetadata::InGap {
                    gap_position,
                    gap_limit,
                },
            ..
        } = meta.exposure()
        {
            let remaining = gap_slots_remaining(gap_position, gap_limit);
            if remaining <= self.transparent_gap_warn_threshold {
                warn!(
                    "[{}] transparent recovery window nearly exhausted: {remaining} recoverable \
                     address slot(s) remain (gap_limit={gap_limit}) before getnewaddress can no \
                     longer issue an address recoverable from seed. Increase [pools] \
                     transparent_gap_limit and/or transparent_initial_scan, or fund a lower-index \
                     address.",
                    self.name
                );
            }
        }
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

        let account_id = self.require_account()?;
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        // Lock the shared seed only long enough to derive the spending key; the guard is released
        // before the (long) proving below, so a concurrent `walletlock` fast path can zeroize the
        // resident seed while this send proves with its already-derived local USK.
        let usk = seed_guard(&self.seed).derive_usk(self.network, account_index)?;

        // Fully transparent send (opt-in): when the policy explicitly allows it and *every*
        // recipient is a bare transparent address, fund the payment directly from the wallet's
        // received transparent UTXOs and keep the change transparent - never touching a shielded
        // pool. librustzcash's high-level proposal API can't express this (it has no transparent
        // input selection, and its change accounting has no persistent transparent-change
        // variant), so zecd builds and signs the transaction itself. Any other policy, or any
        // shielded recipient, falls through to the shielded proposal path below (under which a
        // transparent recipient is still paid from shielded notes with shielded change).
        if privacy == SendPrivacy::AllowFullyTransparent {
            if let Some(recipients) = transparent_only_recipients(&self.network, &request)? {
                return self
                    .do_send_transparent(recipients, confirmations, usk, account_id)
                    .await;
            }
        }
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
        // `AllowFullyTransparent` sends are handled inline by `do_send` (they build via the
        // transparent Builder, not the cached-Orchard PCZT prove path that pipelining accelerates),
        // so never queue them for off-actor proving.
        if privacy == SendPrivacy::AllowFullyTransparent || !self.pipeline_eligible() {
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

    /// Build, sign, record, and broadcast a **fully transparent** send: fund the payment directly
    /// from the wallet's received transparent UTXOs and return the change to a fresh wallet-owned
    /// transparent address, never touching a shielded pool. Reachable only from `do_send` under the
    /// `AllowFullyTransparent` privacy policy with all-transparent recipients.
    ///
    /// librustzcash's high-level proposal/change API can't express kept-transparent change, so this
    /// uses the lower-level `zcash_primitives` transaction `Builder` directly: greedy ZIP-317-aware
    /// coin selection over `get_spendable_transparent_outputs`, sign each P2PKH input with the key
    /// derived from the USK transparent component at the input address's `(scope, index)`, and
    /// record the result via `store_transactions_to_be_sent` (which locks the spent UTXOs and
    /// stores raw bytes for the rebroadcast loop). The change UTXO is rediscovered after mining by
    /// the existing `getaddressutxos` receive scan, so this adds no off-chain persistence.
    async fn do_send_transparent(
        &mut self,
        recipients: Vec<(TransparentAddress, Zatoshis)>,
        confirmations: Option<ConfirmationsPolicy>,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        account_id: AccountUuid,
    ) -> Result<TxId, RpcError> {
        use rand::rngs::OsRng;

        let net = self.network;
        let policy = confirmations.unwrap_or(self.confirmations_policy);
        // `self.prover` is an `Arc<LocalTxProver>` (shared for the pipeline); the transaction
        // builder wants `&LocalTxProver`, so deref-coerce through the Arc.
        let prover: &LocalTxProver = &self.prover;
        let db = &mut self.db_data;

        let (txid, raw): (TxId, Vec<u8>) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let fee_rule = Zip317FeeRule::standard();
                let marginal = u64::from(fee_rule.marginal_fee());
                let grace = fee_rule.grace_actions();
                let p2pkh_out_size = fee_rule.p2pkh_standard_output_size();

                let (target_height, _anchor) = db
                    .get_target_and_anchor_heights(std::num::NonZeroU32::MIN)
                    .map_err(RpcError::database_internal)?
                    .ok_or_else(|| {
                        RpcError::wallet("wallet has no chain tip yet; cannot build a transaction")
                    })?;

                // Gather spendable transparent UTXOs across every exposed receiver (external +
                // internal/change), filtered for confirmations/coinbase-maturity/dust by the policy.
                let receivers = db
                    .get_transparent_receivers(account_id, true, true)
                    .map_err(RpcError::database_internal)?;
                let mut utxos: Vec<WalletUtxo> = Vec::new();
                for addr in receivers.keys() {
                    let outs = db
                        .get_spendable_transparent_outputs(
                            addr,
                            target_height,
                            policy,
                            TransparentOutputFilter::All,
                        )
                        .map_err(RpcError::database_internal)?;
                    utxos.extend(outs);
                }
                if utxos.is_empty() {
                    return Err(RpcError::insufficient_funds(
                        "Insufficient funds: 0 spendable transparent UTXOs",
                    ));
                }
                // Greedy: spend the largest UTXOs first to minimize the input count (and the fee).
                utxos.sort_by_key(|u| std::cmp::Reverse(u.value()));

                let recipients_total: u64 = recipients.iter().map(|(_, v)| u64::from(*v)).sum();
                // Exact ZIP-317 output sizing: sum the recipient outputs' serialized sizes (so a
                // P2SH recipient is priced correctly) and price the change output as P2PKH (the
                // change address is always a P2PKH wallet receiver).
                let recip_out_size: usize = recipients
                    .iter()
                    .map(|(a, _)| transparent_txout_size(a))
                    .sum();
                let change_out_size = 8 + 1 + 25; // a P2PKH change TxOut
                let values: Vec<u64> = utxos.iter().map(|u| u64::from(u.value())).collect();
                let (n_selected, change_amount, fee_amount, has_change) =
                    select_transparent_inputs(
                        &values,
                        recipients_total,
                        recip_out_size,
                        change_out_size,
                        p2pkh_out_size,
                        marginal,
                        grace,
                    )
                    .ok_or_else(|| {
                        RpcError::insufficient_funds(
                        "Insufficient funds: transparent UTXOs do not cover the amount plus fee",
                    )
                    })?;
                utxos.truncate(n_selected);
                let selected = utxos;
                let fee_amount = Zatoshis::from_u64(fee_amount)
                    .map_err(|e| RpcError::misc(format!("fee value: {e}")))?;

                let mut builder = Builder::new(
                    net,
                    BlockHeight::from(target_height),
                    BuildConfig::Standard {
                        sapling_anchor: None,
                        orchard_anchor: None,
                    },
                );

                // Add and key each transparent input. The signing key is derived from the USK
                // transparent component at the input address's recorded `(scope, index)`; the
                // builder matches each input to its key by public key.
                let mut signing_set = TransparentSigningSet::new();
                let mut spent: Vec<zcash_transparent::bundle::OutPoint> = Vec::new();
                let acct_priv = usk.transparent();
                for utxo in &selected {
                    let addr = utxo.recipient_address();
                    let meta = db
                        .get_transparent_address_metadata(account_id, addr)
                        .map_err(RpcError::database_internal)?
                        .ok_or_else(|| {
                            RpcError::wallet("missing key metadata for an owned transparent UTXO")
                        })?;
                    let (scope, index) = match meta.source() {
                        TransparentAddressSource::Derived {
                            scope,
                            address_index,
                        } => (*scope, *address_index),
                        // Other sources (imported standalone keys/scripts) only exist with the
                        // `transparent-key-import` feature, which zecd does not enable.
                        #[allow(unreachable_patterns)]
                        _ => {
                            return Err(RpcError::wallet(
                                "cannot sign a non-derived transparent UTXO",
                            ))
                        }
                    };
                    let sk = acct_priv.derive_secret_key(scope, index).map_err(|e| {
                        RpcError::wallet(format!("transparent key derivation failed: {e}"))
                    })?;
                    let pubkey = signing_set.add_key(sk);
                    builder
                        .add_transparent_p2pkh_input(
                            pubkey,
                            utxo.outpoint().clone(),
                            utxo.txout().clone(),
                        )
                        .map_err(|e| RpcError::wallet(format!("add transparent input: {e}")))?;
                    spent.push(utxo.outpoint().clone());
                }

                // Recipient outputs (vout 0..n), then the transparent change output (if any) to a
                // wallet-owned address.
                for (addr, amt) in &recipients {
                    builder
                        .add_transparent_output(addr, *amt)
                        .map_err(|e| RpcError::wallet(format!("add transparent output: {e}")))?;
                }
                let change_recipient: Option<(TransparentAddress, Zatoshis)> = if has_change {
                    let change_val = Zatoshis::from_u64(change_amount)
                        .map_err(|e| RpcError::misc(format!("change value: {e}")))?;
                    // Prefer an **internal** (change-scope) address: the BIP-32 internal chain is the
                    // change chain, never handed out as a receive address, so an output there is
                    // recognized as change (hidden from history, and distinguished from a deliberate
                    // self-send to an external address) and is recovered on a from-seed restore via
                    // the internal gap chain. librustzcash seeds internal gap addresses at account
                    // creation but exposes no public "reserve next internal address" call, so pick
                    // the gap-start internal receiver from the exposed set. Fall back to a fresh
                    // external address if none is available (still wallet-owned and recoverable,
                    // just shown as a self-transfer).
                    let change_addr = pick_internal_change_address(db, account_id)
                        .map(Ok)
                        .unwrap_or_else(|| {
                            let (ua, _idx) = db
                                .get_next_available_address(
                                    account_id,
                                    crate::pools::transparent_extraction_request(),
                                )
                                .map_err(RpcError::database_internal)?
                                .ok_or_else(|| {
                                    RpcError::wallet(
                                        "could not derive a transparent change address",
                                    )
                                })?;
                            ua.transparent().copied().ok_or_else(|| {
                                RpcError::wallet(
                                    "derived change address has no transparent receiver",
                                )
                            })
                        })?;
                    builder
                        .add_transparent_output(&change_addr, change_val)
                        .map_err(|e| RpcError::wallet(format!("add change output: {e}")))?;
                    Some((change_addr, change_val))
                } else {
                    None
                };

                let result = builder
                    .build(&signing_set, &[], &[], OsRng, prover, prover, &fee_rule)
                    .map_err(|e| {
                        RpcError::wallet(format!("transparent transaction build failed: {e}"))
                    })?;
                let tx = result.transaction();
                let txid = tx.txid();
                let mut raw = Vec::new();
                tx.write(&mut raw)
                    .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;

                // Record the send so the spent UTXOs are locked (no double-spend), the raw tx rides
                // the rebroadcast loop, and history reflects the outgoing payment. The change output
                // is recorded as an external transparent output to our own address; the receive scan
                // re-adds it as a spendable UTXO once mined.
                let mut outputs: Vec<SentTransactionOutput<AccountUuid>> = Vec::new();
                for (i, (addr, amt)) in recipients.iter().enumerate() {
                    outputs.push(SentTransactionOutput::from_parts(
                        i,
                        Recipient::External {
                            recipient_address: Address::Transparent(*addr).to_zcash_address(&net),
                            output_pool: PoolType::Transparent,
                        },
                        *amt,
                        None,
                    ));
                }
                if let Some((change_addr, change_val)) = change_recipient {
                    outputs.push(SentTransactionOutput::from_parts(
                        recipients.len(),
                        Recipient::External {
                            recipient_address: Address::Transparent(change_addr)
                                .to_zcash_address(&net),
                            output_pool: PoolType::Transparent,
                        },
                        change_val,
                        None,
                    ));
                }
                let sent = SentTransaction::new(
                    tx,
                    time::OffsetDateTime::now_utc(),
                    target_height,
                    account_id,
                    &outputs,
                    fee_amount,
                    &spent,
                );
                db.store_transactions_to_be_sent(std::slice::from_ref(&sent))
                    .map_err(RpcError::database_internal)?;

                Ok((txid, raw))
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

    /// Query the upstream for all txids touching a transparent address in `[start, end]`
    /// (`getaddresstxids`). A transport failure drops the client (so the next op reconnects) and
    /// surfaces as `Err`; an unseen address simply yields an empty list.
    async fn fetch_transparent_txids(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> Result<Vec<TxId>, RpcError> {
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| RpcError::misc(format!("connect to upstream: {e}")))?;
        }
        let result = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| RpcError::misc("not connected to upstream"))?;
            tokio::time::timeout(
                UNARY_RPC_TIMEOUT,
                client.transparent_txids(addresses, start, end),
            )
            .await
            .map_err(|_| anyhow!("getaddresstxids timed out after {UNARY_RPC_TIMEOUT:?}"))
            .and_then(|r| r)
        };
        match result {
            Ok(txids) => Ok(txids),
            Err(e) => {
                self.mark_disconnected(format!("transparent txid query failed: {e}"));
                self.update_status();
                Err(RpcError::misc(format!(
                    "transparent txid query failed: {e}"
                )))
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
        // Bind the decrypted seed to the account before holding it unlocked: the seed must
        // derive the account's UFVK, or keys.toml and the wallet database describe different
        // wallets. For an encrypted wallet this is the first moment the check is possible (the
        // seed is never resident at startup), and it retroactively validates a
        // trust-on-first-use pin taken then. Skipped while a bootstrap is pending (no account
        // yet); the bootstrap creates the account from this same seed and verifies the pin.
        if let (Some(id), Some(index)) = (self.account_id, self.account_index) {
            let expected = binding::account_ufvk_encoded(self.network, &self.db_data, id)
                .map_err(|e| RpcError::wallet(format!("reading the wallet account: {e}")))?;
            let derived = binding::seed_ufvk_encoded(self.network, &seed, index)
                .map_err(|e| RpcError::wallet(format!("deriving from the seed: {e}")))?;
            if derived != expected {
                return Err(RpcError::wallet(
                    "Error: The decrypted seed does not derive this wallet's account; \
                     keys.toml and the wallet database disagree (one of them was replaced or \
                     belongs to a different wallet). Refusing to unlock.",
                ));
            }
        }
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
    use super::gap_slots_remaining;
    use super::preexpose_progress_stats;
    use super::sanitize_upstream_msg;
    use super::select_transparent_inputs;

    #[test]
    fn preexpose_progress_stats_computes_pct_rate_eta() {
        // 1000 of 100000 in a 30s window where 1000 were just exposed: 1% done, ~33 addr/s,
        // ETA = 99000/33.3 ≈ 2970s.
        let (pct, rate, eta) = preexpose_progress_stats(1_000, 100_000, 1_000, 30.0);
        assert!((pct - 1.0).abs() < 1e-9, "pct {pct}");
        assert!((rate - 1_000.0 / 30.0).abs() < 1e-9, "rate {rate}");
        assert_eq!(eta, "~2970s");
    }

    #[test]
    fn preexpose_progress_stats_guards_divides() {
        // Zero-length window: rate must be 0 (not inf/NaN) and ETA "unknown".
        let (pct, rate, eta) = preexpose_progress_stats(500, 1_000, 500, 0.0);
        assert_eq!(rate, 0.0);
        assert_eq!(eta, "unknown");
        assert!((pct - 50.0).abs() < 1e-9);

        // A stalled rate (did = 0 over a real window) also yields no ETA, never a divide-by-zero.
        let (_, rate, eta) = preexpose_progress_stats(500, 1_000, 0, 30.0);
        assert_eq!(rate, 0.0);
        assert_eq!(eta, "unknown");

        // total = 0 (degenerate): treated as fully complete, no NaN from 0/0.
        let (pct, _, _) = preexpose_progress_stats(0, 0, 0, 30.0);
        assert_eq!(pct, 100.0);

        // Completion: 100% and a finite ETA.
        let (pct, _, eta) = preexpose_progress_stats(1_000, 1_000, 1_000, 30.0);
        assert_eq!(pct, 100.0);
        assert_eq!(eta, "~0s");
    }

    #[test]
    fn gap_slots_remaining_counts_down_and_saturates() {
        // First address in a fresh gap of 20: 19 slots remain after it.
        assert_eq!(gap_slots_remaining(0, 20), 19);
        // Mid-gap.
        assert_eq!(gap_slots_remaining(14, 20), 5);
        // The last allocatable address: no slots remain.
        assert_eq!(gap_slots_remaining(19, 20), 0);
        // Beyond the gap (shouldn't happen via the in-window path) saturates at 0, never panics.
        assert_eq!(gap_slots_remaining(25, 20), 0);
        assert_eq!(gap_slots_remaining(u32::MAX, 1), 0);
        // Degenerate gap_limit = 1: the single address leaves nothing.
        assert_eq!(gap_slots_remaining(0, 1), 0);
    }

    // ZIP-317 standard parameters (mirrors `zip317::FeeRule::standard`), so the selection tests
    // exercise the exact fee the builder will compute.
    const MARGINAL: u64 = 5_000;
    const GRACE: usize = 2;
    // A standard P2PKH transparent TxOut: 8 (value) + 1 (script-len) + 25 (scriptPubKey).
    const P2PKH_OUT: usize = 8 + 1 + 25;

    #[test]
    fn transparent_selection_keeps_change_when_above_zero() {
        // 1 ZEC UTXO, pay 0.5 ZEC to one P2PKH recipient. Fee for 1-in/2-out = marginal * max(2,2).
        let (n, change, fee, has_change) = select_transparent_inputs(
            &[100_000_000],
            50_000_000,
            P2PKH_OUT,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(has_change);
        assert_eq!(fee, MARGINAL * 2); // grace floor dominates for a tiny tx
        assert_eq!(change, 100_000_000 - 50_000_000 - fee);
        // Balance holds exactly: inputs == recipients + change + fee.
        assert_eq!(100_000_000, 50_000_000 + change + fee);
    }

    #[test]
    fn transparent_selection_exact_cover_emits_no_change() {
        // Inputs cover recipient + the no-change fee exactly → no change output.
        let total = 50_000_000 + MARGINAL * 2;
        let (n, change, fee, has_change) = select_transparent_inputs(
            &[total],
            50_000_000,
            P2PKH_OUT,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(!has_change);
        assert_eq!(change, 0);
        assert_eq!(fee, MARGINAL * 2);
        assert_eq!(total, 50_000_000 + fee);
    }

    #[test]
    fn transparent_selection_accumulates_multiple_inputs() {
        // No single UTXO covers the payment; two are pulled (largest first).
        let (n, change, fee, has_change) = select_transparent_inputs(
            &[60_000_000, 60_000_000],
            100_000_000,
            P2PKH_OUT,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE,
        )
        .unwrap();
        assert_eq!(n, 2);
        assert!(has_change);
        // 2-in/2-out → max(2,2)=2 actions.
        assert_eq!(fee, MARGINAL * 2);
        assert_eq!(change, 120_000_000 - 100_000_000 - fee);
        assert_eq!(120_000_000, 100_000_000 + change + fee);
    }

    #[test]
    fn transparent_selection_fee_scales_with_input_count() {
        // Three inputs, one recipient + change → 3-in/2-out → max(3,2)=3 actions.
        let values = [40_000_000, 40_000_000, 40_000_000];
        let (n, change, fee, has_change) = select_transparent_inputs(
            &values,
            100_000_000,
            P2PKH_OUT,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE,
        )
        .unwrap();
        assert_eq!(n, 3);
        assert!(has_change);
        assert_eq!(fee, MARGINAL * 3);
        assert_eq!(120_000_000, 100_000_000 + change + fee);
    }

    #[test]
    fn transparent_selection_fee_scales_with_output_count() {
        // One large input, two recipients + change → 1-in/3-out → max(grace, max(1,3)) = 3 actions.
        let (n, change, fee, has_change) = select_transparent_inputs(
            &[100_000_000],
            40_000_000,    // two recipients summing to 0.4 ZEC...
            2 * P2PKH_OUT, // ...priced as two P2PKH outputs
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE,
        )
        .unwrap();
        assert_eq!(n, 1);
        assert!(has_change);
        assert_eq!(fee, MARGINAL * 3); // 3 outputs dominate the action count
        assert_eq!(100_000_000, 40_000_000 + change + fee);
    }

    #[test]
    fn transparent_selection_prices_p2sh_outputs_smaller() {
        // 17 P2SH recipient outputs (32 bytes each) total 544 bytes → ceil(544/34) = 16 output
        // actions, one fewer than the 17 a naive per-output count would charge. This is exactly how
        // the builder's ZIP-317 fee rule sizes them; a count-based formula would mis-fee here.
        const P2SH_OUT: usize = 8 + 1 + 23;
        let recip_out_size = 17 * P2SH_OUT; // 544 bytes
        let (_n, _change, fee, _has_change) = select_transparent_inputs(
            &[100_000_000],
            1_000_000,
            recip_out_size,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE,
        )
        .unwrap();
        // With change: total out = 544 + 34 = 578 → ceil(578/34) = 17 actions; 1 input → fee = 17m.
        assert_eq!(fee, MARGINAL * 17);
    }

    #[test]
    fn transparent_only_recipients_detects_all_transparent_and_empty() {
        use super::transparent_only_recipients;
        use crate::network::ZNetwork;
        use zcash_keys::address::Address;
        use zcash_protocol::value::Zatoshis;
        use zcash_transparent::address::TransparentAddress;
        use zip321::{Payment, TransactionRequest};

        let net = ZNetwork::Test;
        let taddr = |b: u8| {
            Address::Transparent(TransparentAddress::PublicKeyHash([b; 20])).to_zcash_address(&net)
        };

        // Two bare transparent recipients → Some, with amounts preserved in order.
        let req = TransactionRequest::new(vec![
            Payment::without_memo(taddr(1), Zatoshis::const_from_u64(50_000_000)),
            Payment::without_memo(taddr(2), Zatoshis::const_from_u64(10_000_000)),
        ])
        .unwrap();
        let parsed = transparent_only_recipients(&net, &req)
            .unwrap()
            .expect("all-transparent recipients are recognized");
        assert_eq!(parsed.len(), 2);
        let total: u64 = parsed.iter().map(|(_, v)| u64::from(*v)).sum();
        assert_eq!(total, 60_000_000);

        // An empty request is not a fully-transparent send (falls through to the normal path).
        assert!(
            transparent_only_recipients(&net, &TransactionRequest::empty())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn transparent_selection_insufficient_funds_returns_none() {
        // Total is below recipient + minimum fee, even after exhausting every UTXO.
        assert!(select_transparent_inputs(
            &[10_000_000],
            50_000_000,
            P2PKH_OUT,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE
        )
        .is_none());
        assert!(select_transparent_inputs(
            &[],
            1,
            P2PKH_OUT,
            P2PKH_OUT,
            P2PKH_OUT,
            MARGINAL,
            GRACE
        )
        .is_none());
    }

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
