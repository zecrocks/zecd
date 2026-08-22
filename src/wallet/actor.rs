//! The per-wallet actor: the single owner/writer of the `WalletDb`, running the sync loop
//! and serving writer commands (address generation, sends, lock/unlock) from RPC handlers.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use nonempty::NonEmpty;
use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, create_proposed_transactions, decrypt_and_store_transaction,
    extract_and_store_transaction_from_pczt,
    input_selection::{
        CoinbasePolicy, GreedyInputSelector, LockFilter, LockedInputPolicy, SpendPolicy,
        TransparentSpendPolicy,
    },
    propose_send_max_transfer, propose_transfer, ConfirmationsPolicy, SpendingKeys, TargetHeight,
};
use zcash_client_backend::data_api::{
    Account, AccountBirthday, AccountPurpose, AccountSource, CoinbaseFilter, InputSource,
    MaxSpendMode, NoteRetention, SentTransaction, SentTransactionOutput, TargetValue,
    TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
};
use zcash_client_backend::fees::{
    standard::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule,
    TransactionBalance,
};
use zcash_client_backend::proposal::{Proposal, ShieldedInputs};
use zcash_client_backend::proto::service;
use zcash_client_backend::wallet::{
    OvkPolicy, Recipient, TransparentAddressSource, WalletTransparentOutput,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::{AccountUuid, FsBlockDb};
use zcash_keys::address::Address;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_primitives::transaction::fees::{transparent as transparent_fees, FeeRule as _};
use zcash_primitives::transaction::Transaction;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{PoolType, ShieldedPool, TxId};
use zcash_transparent::address::TransparentAddress;
use zcash_transparent::builder::TransparentSigningSet;
use zip32::DiversifierIndex;
use zip321::TransactionRequest;

use crate::backend::Server;
use crate::backoff::Backoff;
use crate::chain::{
    AnySource, BroadcastOutcome, ChainSource, MempoolStream, ServerInfo, TxEvidence,
    UnsupportedUpgrade,
};
use crate::config::SendPrivacy;
use crate::error::{codes, ErrorDetails, InsufficientFunds, RpcError};
use crate::network::ZNetwork;
use crate::pools::{Receiver, ReceiverSet};
use crate::sync::engine;
use crate::wallet::binding;
use crate::wallet::keys::{self, SeedKeeper};
use crate::wallet::open::{self, WriteDb};
use crate::wallet::read;
use crate::wallet::{
    make_handle, store, ConnState, DerivedAddress, FirstSeen, MergePlan, MergeSource, MergeWork,
    RawTx, ReceiverRequest, SendSource, SharedSeed, SyncStatus, WalletCommand, WalletHandle,
};

/// The concrete error type returned by `propose_transfer` / `create_proposed_transactions`
/// for our `WalletDb`. Naming it pins the otherwise-unconstrained commitment-tree error
/// parameter so `map_err` closures can infer their argument type (mirrors zcash-devtool's
/// `WalletErrorT`). It sits here rather than in `error.rs` because it is typed against the
/// wallet crates, which stay confined to `wallet/`; the shared error module carries only the
/// Bitcoin Core code taxonomy and its string-typed constructors.
type ProposalError = zcash_client_backend::data_api::error::Error<
    zcash_client_sqlite::error::SqliteClientError,
    zcash_client_sqlite::wallet::commitment_tree::Error,
    zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelectorError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_primitives::transaction::fees::zip317::FeeError,
    zcash_client_sqlite::ReceivedNoteId,
>;

/// Note-management defaults for change splitting (match zcash-devtool's send defaults).
const TARGET_NOTE_COUNT: usize = 4;
const MIN_SPLIT_OUTPUT_VALUE: u64 = 10_000_000; // 0.1 ZEC

/// The Orchard (+ Ironwood) proving keys, built once and shared (read-only) across
/// every wallet actor via `Arc`. These are wallet-independent (they're the circuit's keys), and
/// `ProvingKey::build()` is a full `keygen_vk`+`keygen_pk` - seconds of work - so the fused
/// librustzcash send path (which rebuilds the proving key on *every* transaction) pays that
/// cost per send. Building them here once and feeding them to the PCZT prove path eliminates that
/// per-send overhead (the `[spend] cache_proving_key` knob, default on).
///
/// Deliberately **no verifying key**: the extract step's only use for one was a PCZT with no
/// Ironwood actions, and post-NU6.3 - live on both public networks - every send's outputs are
/// Ironwood, so it went unread while costing ~1.2 s of every startup. [`store_pczt`] now always
/// passes `None`, and the extractor generates the right key per bundle on the fly, exactly as it
/// already did for every Ironwood send.
///
/// Two circuit versions exist (orchard `bundle.rs`): a **V2 Orchard** bundle uses `FixedPostNu6_2`,
/// a **V3 Ironwood** bundle uses `PostNu6_3`, and `Bundle::create_proof` rejects a key whose circuit
/// version doesn't match the bundle. A post-NU6.3 send from an Orchard-pool wallet carries *both*
/// bundles (V2 spends of legacy Orchard notes + V3 Ironwood outputs/change), so both proving keys
/// are needed. NU6.3 is activated on **both mainnet (height 3_428_143) and testnet (4_134_000)**,
/// so `ironwood_pk` is built on both; it is `None` only where the network carries no NU6.3
/// activation height at all - in practice a regtest chain started without
/// `ZECD_REGTEST_NU63_HEIGHT` - where the PostNu6_3 keygen would be ~4.5 s of wasted startup for a
/// key no send can use.
pub struct ProvingKeyCache {
    /// `FixedPostNu6_2` proving key - proves the V2 Orchard bundle.
    orchard_pk: orchard::circuit::ProvingKey,
    /// `PostNu6_3` proving key - proves the V3 Ironwood bundle. `None` only when the network has
    /// no NU6.3 activation height at all (so no send produces an Ironwood bundle); mainnet and
    /// testnet both have one. See [`ProvingKeyCache::build`].
    ironwood_pk: Option<orchard::circuit::ProvingKey>,
}

impl ProvingKeyCache {
    /// Build the cached proving keys. Expensive (full key generation); call off the async runtime
    /// (e.g. under `spawn_blocking`) - [`ProvingKeys::spawn_build`] is the wiring that does.
    /// `build_ironwood` also builds the `PostNu6_3` proving key for the Ironwood bundle; pass it
    /// iff the network has a NU6.3 activation height - **true on both mainnet and testnet**, and
    /// on regtest only when `ZECD_REGTEST_NU63_HEIGHT` is set - so only a NU6.3-less regtest
    /// chain skips a keygen it can't use.
    ///
    /// The two keygens are independent, so they run on **separate threads**: the wall clock is the
    /// slower of the two rather than their sum (measured on 4 cores: 1.8 s + 2.0 s sequential).
    /// Each `keygen_pk` is itself rayon-parallel (orchard's `multicore`, on via
    /// `zcash_primitives`' default features), so on a single-core host the two simply interleave
    /// and cost what they always did.
    pub fn build(build_ironwood: bool) -> Self {
        use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
        let (orchard_pk, ironwood_pk) = std::thread::scope(|scope| {
            let ironwood = build_ironwood
                .then(|| scope.spawn(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3)));
            let orchard_pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
            // A keygen panic is not recoverable (it means this build cannot prove at all), so
            // propagate it to the caller's `spawn_blocking`, which reports it as a failed build.
            let ironwood_pk = ironwood.map(|h| h.join().expect("Ironwood keygen panicked"));
            (orchard_pk, ironwood_pk)
        });
        ProvingKeyCache {
            orchard_pk,
            ironwood_pk,
        }
    }
}

/// The handle the daemon and every actor hold: a [`ProvingKeyCache`] that is **built in the
/// background** rather than on the startup critical path.
///
/// Key generation is seconds of CPU (measured on 4 cores, release: 1.8 s for the Orchard key,
/// 2.0 s for the Ironwood one; several times that single-threaded or on a small VPS). Doing it
/// before the daemon bound its listeners made zecd unreachable - no `/healthz`, no RPC, no
/// sync - for that whole window, to serve a key that **only sends need**. So `daemon::run` now
/// kicks off [`Self::spawn_build`] and carries straight on to spawning actors and binding the
/// servers; the first send awaits [`Self::get`], which resolves immediately once the background
/// build has finished (and, on a daemon that never sends, is never awaited at all).
///
/// [`tokio::sync::OnceCell`] gives the needed semantics for free: concurrent callers of
/// `get_or_try_init` wait for the in-flight initializer instead of starting a second keygen, and
/// a send arriving before the background task even ran simply drives the build itself.
pub struct ProvingKeys {
    cell: tokio::sync::OnceCell<Arc<ProvingKeyCache>>,
    build_ironwood: bool,
}

impl ProvingKeys {
    /// Create the (empty) handle. Nothing is built until [`Self::spawn_build`] or [`Self::get`].
    pub fn new(build_ironwood: bool) -> Arc<Self> {
        Arc::new(ProvingKeys {
            cell: tokio::sync::OnceCell::new(),
            build_ironwood,
        })
    }

    /// Start building the keys in the background. Returns immediately; the daemon carries on
    /// binding its listeners while the keygen runs on a blocking thread.
    pub fn spawn_build(self: &Arc<Self>) {
        let keys = Arc::clone(self);
        tokio::spawn(async move {
            let started = Instant::now();
            match keys.get().await {
                Ok(_) => info!(
                    "Orchard proving key{} ready in {:?}",
                    if keys.build_ironwood {
                        " + Ironwood (PostNu6_3) proving key"
                    } else {
                        ""
                    },
                    started.elapsed()
                ),
                // Only a panic inside the keygen gets here. Sends will retry (and fail the same
                // way); everything else - sync, reads - keeps working, so this is not fatal.
                Err(e) => error!("building the Orchard proving key failed: {e}"),
            }
        });
    }

    /// The built keys, awaiting the background build if it is still running.
    pub async fn get(&self) -> Result<Arc<ProvingKeyCache>, RpcError> {
        let build_ironwood = self.build_ironwood;
        self.cell
            .get_or_try_init(|| async move {
                tokio::task::spawn_blocking(move || {
                    Arc::new(ProvingKeyCache::build(build_ironwood))
                })
                .await
                .map_err(|e| {
                    RpcError::wallet(format!("building the Orchard proving key failed: {e}"))
                })
            })
            .await
            .cloned()
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

/// How many consecutive *identical* apply-side sync failures before the log escalates from the
/// raw error to wallet-database recovery guidance. A one-off apply error can be transient (a
/// reorg racing the batch); the same error failing this many paced retries in a row is the
/// stuck loop an operator otherwise stares at for thousands of iterations with no hint.
const PERSISTENT_SYNC_ERROR_THRESHOLD: u32 = 3;

/// The operator action line for an unsupported-network-upgrade condition. One place, so the
/// connect-time announcement and the sync-error attribution can't drift apart.
const UPGRADE_GUIDANCE: &str = "Update to the latest zecd release; if you are already on the \
     latest release, please report this at https://forum.zcashcommunity.com";

/// Whether a sync failure is **terminal** - retrying it can never succeed, so the actor halts
/// this wallet's scan instead of pacing the same failure forever.
///
/// Exactly one class qualifies today: [`engine::UnrecoverableReorg`], where no truncation target
/// below the conflicting block exists, so the block cannot be removed and every batch re-hits it.
/// Everything else is retried - a transport error is fixed by reconnecting, and even a repeated
/// apply-side failure (`engine::WalletApplyError`) can clear once the operator updates zecd for a
/// network upgrade the running build cannot parse. Keep it that way: halting on a class that can
/// recover on its own would strand a wallet that only needed to wait.
fn sync_failure_is_terminal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<engine::UnrecoverableReorg>().is_some()
}

/// Build the recovery guidance (if any) to append to a failed sync pass's log line.
///
/// Only *apply-side* failures ([`engine::WalletApplyError`]: the upstream served the blocks,
/// committing them to the wallet DB failed) are ever attributed - a transport failure is fixed
/// by reconnecting, and telling an operator to rebuild their wallet over a zebra outage would
/// be actively harmful. Within that class:
///  * an unsupported network upgrade already ruling the chain explains the failure outright
///    (the scan is hitting post-activation blocks this build cannot parse), so it is named
///    immediately - this is the "old zecd after NU6.3 activated" loop; and
///  * otherwise, once the same error has repeated [`PERSISTENT_SYNC_ERROR_THRESHOLD`] times,
///    the wallet database itself is the prime suspect (e.g. a shardtree `Insert(Conflict)`
///    that no restart or version upgrade clears), and the guidance points at the
///    `zecd rescan` rebuild.
///
/// Pure so it is unit-testable without a [`WalletActor`]; the actor supplies the streak and
/// the already-relevant upgrade (active, or pending with an activation height at/below the
/// upstream tip).
fn sync_failure_hint(
    apply_side: bool,
    streak: u32,
    wallet: &str,
    upgrade: Option<&UnsupportedUpgrade>,
) -> Option<String> {
    if !apply_side {
        return None;
    }
    if let Some(u) = upgrade {
        let height = u
            .activation_height
            .map(|h| format!(", activated at height {h}"))
            .unwrap_or_default();
        return Some(format!(
            "likely cause: this zecd build does not support network upgrade '{}' (consensus \
             branch 0x{:08x}{height}), so blocks past its activation cannot be scanned. \
             {UPGRADE_GUIDANCE}",
            sanitize_upstream_msg(&u.name),
            u.branch_id,
        ));
    }
    if streak >= PERSISTENT_SYNC_ERROR_THRESHOLD {
        return Some(format!(
            "the same error has now failed {streak} consecutive sync passes: the upstream is \
             serving blocks but the wallet database cannot apply them, which restarting or \
             upgrading zecd will not fix if the database itself is inconsistent. Stop the \
             daemon and run `zecd rescan --wallet {wallet}` to rebuild the wallet database \
             from the seed (keys.toml is kept; funds and history are re-derived by rescanning \
             from the wallet birthday). If this looks like a zecd bug, please report it at \
             https://forum.zcashcommunity.com"
        ));
    }
    None
}

/// The reconnect deadline to set after a sync error: a fixed floor past `now`. Extracted as a
/// free function (rather than inlined into the run loop) so the pacing is unit-testable without
/// standing up a full [`WalletActor`]; the run loop's sync-error arm is its only caller.
fn sync_error_retry_deadline(now: Instant) -> Instant {
    now + SYNC_ERROR_RETRY_INTERVAL
}

/// How many transaction-enhancement requests to service per `enhance_step` call before
/// yielding back to the actor loop. Enhancement runs only once the block scan is caught up,
/// but it can be a multi-hour backlog on a from-birthday restore (one upstream
/// `getrawtransaction` then decrypt/store per request). Draining it in bounded batches - instead
/// of one monolithic pass - keeps the single-writer actor responsive: queued commands (sends) are
/// serviced between batches and the shrinking backlog is republished on `SyncStatus` after each
/// one. At ~0.3s/request this is a few seconds of work per batch.
const ENHANCE_BATCH: usize = 16;

/// How often to emit an enhancement-drain progress heartbeat (throttled by wall time, like the
/// transparent pre-exposure heartbeat). The `pending_enhancements` count alone can sit flat for
/// a long drain even while requests are being serviced continuously - e.g. before
/// `TransactionsInvolvingAddress` requests were serviced through to the tip, each serviced
/// window immediately spawned its successor, so the snapshot count measured the number of
/// in-progress address crawls, not the remaining work, and a half-hour drain read as a stall.
/// The heartbeat makes forward progress visible in the log regardless of how the count moves.
const ENHANCE_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// The largest pending enhancement backlog for which [`SyncStatus::enhanced_through`] is
/// computed exactly. Resolving an `Enhancement`/`GetStatus` request to a height is one point
/// query, and a post-restore drain holds tens of thousands of requests, so past this bound the
/// watermark reports "nothing known to be enhanced" instead of running a five-figure query
/// count on every status update. A consumer waiting on a backlog that size is waiting for it to
/// drain regardless.
const ENHANCED_THROUGH_MAX_PROBE: usize = 2048;

/// What rebuilds a wallet's account on the bootstrap path (an empty data directory beside a
/// populated `keys.toml`). Both sources are recorded in `keys.toml` itself and neither is
/// recoverable from anywhere else on disk, which is why the bootstrap decision is made once at
/// spawn and carried, rather than re-read per attempt.
enum BootstrapKey {
    /// A spending wallet: `create_account` from the decrypted seed. Waits for the seed to be
    /// available (immediately for an identity/auto-unlock wallet, at the first
    /// `walletpassphrase` for an encrypted one).
    Seed,
    /// A watch-only wallet: `import_account_ufvk` from the key pinned in `keys.toml`. Needs no
    /// secret, so it runs as soon as the upstream can serve the birthday tree state.
    Ufvk(Box<UnifiedFullViewingKey>),
}

/// The enhancement watermark: the height through which every transaction has had its full data
/// fetched, given the scanned frontier and the lowest height any pending request still refers to.
///
/// Nothing above `fully_scanned` has been scanned at all, so the watermark can never exceed it.
/// A pending request at height `h` means `h` itself is not yet complete, so the watermark stops
/// at `h - 1`. An empty backlog (`lowest_pending` of `None`) means the whole scanned range is
/// enhanced. Pure so the boundary cases are unit-testable without an actor.
fn enhanced_through(fully_scanned: u32, lowest_pending: Option<u32>) -> u32 {
    match lowest_pending {
        Some(h) => fully_scanned.min(h.saturating_sub(1)),
        None => fully_scanned,
    }
}

/// Whether a [`TransactionDataRequest`] is one zecd can actually service (and therefore one that
/// counts toward the enhancement backlog). All three variants drain: `GetStatus`/`Enhancement` via
/// `fetch_full_tx`, and `TransactionsInvolvingAddress` via the transparent address-index query
/// (`fetch_transparent_tx_evidence` + `notify_address_checked`), which converges once the address is
/// recorded as checked, so it doesn't pin the backlog above zero.
fn is_serviceable_request(req: &TransactionDataRequest) -> bool {
    matches!(
        req,
        TransactionDataRequest::GetStatus(_)
            | TransactionDataRequest::Enhancement(_)
            | TransactionDataRequest::TransactionsInvolvingAddress(_)
    )
}

/// The inclusive block range `(start, end)` to actually check when servicing a
/// `TransactionsInvolvingAddress` request, given the request's `block_range_start` and the
/// current chain tip - or `None` when there is nothing checkable yet.
///
/// librustzcash windows its transparent spend-detection requests to roughly one tx-expiry delta
/// (~40 blocks) past the last height each address was verified unspent at, and re-emits the next
/// window only after `notify_address_checked` records the previous one. Serviced literally, that
/// walks a restored wallet's UTXO from its funding height to the tip one window at a time -
/// thousands of sequential `getaddresstxids` round trips per address on a deep restore (~3300 on
/// a 135k-block range), which made the enhancement drain take several times longer than the block
/// scan itself. The window exists for lightwalletd-style servers (bounded queries, per-request
/// decorrelation via `request_at`); zebra's always-on address index serves any range in one
/// indexed call, and the upstream docs explicitly permit a trusted chain-data source to ignore
/// the decorrelation constraint. So zecd checks straight through to the chain tip in one query.
///
/// The start is clamped to 1 (zebra cannot serve genesis). `None` - nothing checkable - happens
/// when the start is beyond the tip, e.g. a spend-search request whose funding tx is still
/// unmined (librustzcash emits those with `block_range_start` = the generation-time tip and a
/// windowed end beyond it); the caller must then skip `notify_address_checked` entirely, since
/// notifying any height the backend's `as_of == block_range_end - 1` consistency check would
/// accept would claim a check that never ran.
fn tia_check_range(block_range_start: u32, chain_tip: u32) -> Option<(u32, u32)> {
    let start = block_range_start.max(1);
    (start <= chain_tip).then_some((start, chain_tip))
}

/// Why a connected upstream is unusable for this wallet, if it is: a transparent-enabled wallet
/// needs a backend whose block scan carries transparent data.
///
/// zecd used to work around a server that could not (lightwalletd before 0.5.0) by polling the
/// address index per address - a whole parallel receive-discovery path, quadratically expensive
/// on a large address set, and one that only ever mattered for servers the ecosystem has since
/// moved off. Now the requirement is stated instead: transparent receives ride the block scan on
/// every supported backend. Refusing is what keeps the removal safe, since the failure it
/// replaces would otherwise be silent - transparent funds simply never appearing.
///
/// Shielded-only wallets (the default) are unaffected and work against any server.
fn transparent_capability_error(
    transparent_enabled: bool,
    block_scan_covers: bool,
) -> Option<&'static str> {
    (transparent_enabled && !block_scan_covers).then_some(
        "this wallet has transparent receiving enabled ([pools] transparent = true), but the \
         upstream lightwalletd does not advertise that it serves transparent data in compact \
         blocks. Transparent receives would never be discovered. Note that no released \
         lightwalletd populates the advertisement yet, so a 0.5.x server that does serve the \
         data still reports this: set [backend] assume_transparent_in_compact_blocks = true to \
         assert the capability. Otherwise upgrade the server, point [backend] server at your \
         own zebra, or disable [pools] transparent",
    )
}

/// Height-based block-scan progress in `[0, 1]`: how much of the wallet's scan range
/// (birthday..chain tip) `fully_scanned` has covered.
///
/// This deliberately does NOT use librustzcash's note-weighted `progress().scan()` ratio: that
/// ratio is computed over the *tip-priority* scan range, so on a from-birthday restore it reads
/// 1.0 from the very first status update while the lower-priority historical ranges - the actual
/// hours of scanning - are still climbing `fully_scanned`. Surfacing it as
/// `getwalletinfo.scanning.progress` invited operators to report a scan complete that had barely
/// begun (the same trap `/readyz` avoids by gating on the height gap; see `HealthConfig`). The
/// height ratio moves in lockstep with the block counter, so it is honest for the whole scan.
/// An empty range (tip at or below the birthday - a fresh wallet) is complete, not `0/0`.
fn scan_progress_ratio(birthday: u32, fully_scanned: u32, chain_tip: u32) -> f64 {
    let total = chain_tip.saturating_sub(birthday);
    if total == 0 {
        return 1.0;
    }
    (f64::from(fully_scanned.saturating_sub(birthday)) / f64::from(total)).clamp(0.0, 1.0)
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
    /// Heartbeat throttle (rolling-window rate; also the completion-time clock).
    throttle: crate::progress::ProgressThrottle,
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
/// while leaving all other panics fully reported. Idempotent: repeated calls (an embedder
/// building several nodes in one process) install the hook once rather than nesting a new
/// wrapper around the previous one on every call.
pub fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if SILENCE_PROGRESS_PANIC.with(|f| f.get()) {
                return;
            }
            default(info);
        }));
    });
}

/// Parameters needed to launch a wallet actor.
pub struct ActorConfig {
    pub name: String,
    pub network: ZNetwork,
    pub engine_dir: PathBuf,
    /// Path to this wallet's `keys.toml` (may live outside `engine_dir`, e.g. a mounted Secret).
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
    /// (`create_proposed_transactions`), which rebuilds the proving key per send. Created once in
    /// `daemon::run` and cloned into every actor (the key is wallet-independent), with the keygen
    /// itself running in the background - a send awaits it. NB: the PCZT path here signs only
    /// Orchard spends, so a wallet that can spend Sapling notes (`enabled_pools` includes
    /// Sapling) falls back to the fused path regardless - see `do_send`.
    pub orchard_keys: Option<Arc<ProvingKeys>>,
    /// Run the proving step off the actor so a long send doesn't freeze sync (`[spend]
    /// pipeline_proving`). Only engages on the cached-Orchard PCZT path; off by default.
    pub pipeline_proving: bool,
    /// Shielded pools this wallet receives into and spends from (change pool selection).
    pub enabled_pools: ReceiverSet,
    /// Receivers included by default in this wallet's Unified Addresses.
    pub default_receivers: ReceiverSet,
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
    engine_dir: PathBuf,
    /// Path to this wallet's `keys.toml` (may live outside `engine_dir`).
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
    enabled_pools: ReceiverSet,
    /// Receivers included by default in this wallet's Unified Addresses.
    default_receivers: ReceiverSet,
    /// Whether this wallet may hand out bare transparent receiving addresses.
    transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` returns a bare transparent address.
    transparent_default: bool,
    /// External transparent gap limit: how far past the issuance frontier (and past each funded
    /// index) receive discovery looks. Together with `transparent_initial_scan` and the default
    /// address's frontier it defines the stateless-restore recovery horizon (see
    /// [`recovery_horizon_for`]).
    transparent_gap_limit: u32,
    /// Initial transparent scan depth: pre-expose external indices `0..N` once so the receive
    /// scan covers them. `0` = off.
    transparent_initial_scan: u32,
    /// Whether `getnewaddress` may issue transparent addresses past the recovery window (warn-only);
    /// `false` fails the call with an actionable error instead.
    transparent_allow_beyond_recovery_window: bool,
    /// Warn when fewer than this many in-window transparent address slots remain before generation
    /// would hit the gap limit.
    transparent_gap_warn_threshold: u32,
    /// The wallet's transparent receive matcher: the recorded receiving + change addresses plus
    /// the in-memory gap lookahead past the issuance frontier (see
    /// [`engine::TransparentMatcher`]). Transient (rebuilt from the DB + viewing key, respects the
    /// stateless invariant). librustzcash never asks us to scan our *receiving* transparent
    /// addresses for incoming funds (only to find spends of UTXOs we already hold), so zecd owns
    /// receive discovery: it matches each scanned block's (and each mempool tx's) transparent
    /// outputs against this set. Matching is O(outputs) with an O(1) membership test, independent
    /// of the set's size - what lets an exchange track ~100k addresses without per-address
    /// requests. `None` until first built; rebuilt lazily when `transparent_set_dirty`.
    transparent_scripts: Option<engine::TransparentMatcher>,
    /// Set when the exposed-address set may have grown (a recorded receive can extend the
    /// transparent gap, exposing new indices), so the next sync pass rebuilds `transparent_scripts`
    /// before matching. `transparent_preexposed` flips once `0..transparent_initial_scan` has been
    /// pre-exposed.
    transparent_set_dirty: bool,
    /// The wallet's unspent transparent outpoints, tested against each scanned block's
    /// transparent inputs so a spend of one of them is discovered by the block scan itself.
    /// `None` until first built; rebuilt when `transparent_unspent_dirty`.
    transparent_unspent: Option<engine::UnspentOutpoints>,
    /// Set whenever the unspent set may have changed (a receive or a spend was recorded, or the
    /// wallet authored a send), so the next pass rebuilds it.
    transparent_unspent_dirty: bool,
    transparent_preexposed: bool,
    /// Live initial-sync progress while it runs (and the final state afterward), for the
    /// heartbeat log and the `getwalletinfo`/`/status` surfaces. `None` until the first chunk;
    /// stays `Some` once started so an operator can poll the completed count too.
    transparent_preexpose: Option<PreexposeProgress>,
    /// Last frontier computed by `rebuild_transparent_set`, for `SyncStatus`.
    transparent_frontier: Option<u32>,
    /// The external transparent frontier a fresh from-seed restore of this account starts with:
    /// one past the account **default address**'s transparent child index. Account creation
    /// always derives and exposes the default Unified Address, whose diversifier index is the
    /// first index valid for *every* receiver the key has - for a key with a Sapling component
    /// that is the first Sapling-valid index, a per-seed value that is 0 for only about half of
    /// all seeds (geometric: >= 3 for ~1 in 8, >= 5 for ~1 in 32). Because every restore of the
    /// seed re-derives and re-exposes the same index, restore coverage - and therefore the
    /// recovery horizon - is anchored here rather than at zero (see
    /// [`recovery_horizon_for`]). Computed once when the account is known (spawn, or bootstrap
    /// adoption); `None` while no account exists or its key has no transparent component.
    transparent_default_frontier: Option<u32>,
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
    pending_bootstrap: Option<(BlockHeight, BootstrapKey)>,
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
    /// Cached Orchard keys for the PCZT send path (`None` = legacy fused path). Built in the
    /// background; a send awaits it. See [`ProvingKeys`].
    orchard_keys: Option<Arc<ProvingKeys>>,
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
    /// Network upgrades the connected upstream reports whose consensus branch IDs this build
    /// does not recognize (captured at each connect from `getblockchaininfo`; see
    /// [`crate::chain::unsupported_upgrades`]). An *active* entry means the chain is already
    /// governed by rules this build can't scan under - the cause behind an otherwise-mysterious
    /// stuck sync loop - and a *pending* one is the advance warning to update zecd before
    /// activation. Drives the connect-time announcements and the sync-error attribution.
    unsupported_upgrades: Vec<UnsupportedUpgrade>,
    /// The display text of the most recent sync error, and how many consecutive sync passes
    /// have failed with exactly it. Reset on any successful pass. A growing streak of the
    /// *same* apply-side error is the "this will not fix itself" signal that escalates the log
    /// from the raw error to recovery guidance (see [`sync_failure_hint`]).
    last_sync_error: Option<String>,
    sync_error_streak: u32,
    /// Sync is stopped for this wallet because a failure that **cannot** succeed on retry was
    /// hit: an [`engine::UnrecoverableReorg`], where no truncation target below the conflict
    /// exists, so the conflicting block can never be removed and every batch re-hits it. The rest
    /// of the actor keeps running - reads, address issuance, the RPC surface - but no further
    /// scan is attempted until the operator rebuilds the wallet database (`zecd rescan`) and
    /// restarts, which clears this (it is in-memory, so a restart always re-tries once).
    ///
    /// Without this the actor retried the identical failure forever, dropping and rebuilding the
    /// upstream connection each time (280 attempts over ten minutes, observed in CI), which looks
    /// like a flaky upstream rather than a wallet that needs rebuilding.
    sync_halted: bool,
    /// Set by [`WalletCommand::SyncNow`]: run a sync pass on the next loop iteration instead of
    /// waiting out `sync_interval`. Consumed (and cleared) at the top of the loop. A plain flag
    /// rather than a wake channel because delivering the command already wakes the idle
    /// `select!` - all this adds is "and treat the next iteration as having work to do".
    force_sync: bool,
    /// Serviceable transaction-data requests already attempted in the current enhancement drain.
    /// Mirrors zcash-devtool/zkv's per-pass `satisfied` set, but carried across `enhance_step`
    /// batches so a request the upstream can't satisfy (left in the DB after servicing) is
    /// re-fetched at most once per drain instead of spinning the batch loop. Cleared whenever a
    /// sync batch does work (new blocks may add or re-satisfy requests). Entries removed from the
    /// DB by librustzcash on success simply never reappear.
    enhance_satisfied: std::collections::BTreeSet<TransactionDataRequest>,
    /// Heartbeat throttle for the current enhancement drain (see [`ENHANCE_LOG_INTERVAL`]).
    /// `None` when no drain is in progress; transient and per-drain, reset whenever the drain
    /// completes or a sync batch does work (which clears `enhance_satisfied`, the
    /// serviced-count baseline).
    enhance_progress: Option<crate::progress::ProgressThrottle>,
    /// Graceful-shutdown signal (see [`ActorConfig::shutdown`]).
    shutdown: watch::Receiver<bool>,
}

/// Open the wallet, derive its account info, optionally unlock the seed, build the prover,
/// and spawn the actor task. Returns a clonable handle plus the task's join handle (awaited
/// at shutdown so the wallet DB closes cleanly before the runtime is torn down).
///
/// The whole setup - and the actor task it spawns - runs inside a `wallet` span carrying the
/// wallet name, so every event emitted on the actor (including the sync engine and the chain
/// clients it drives) is attributable to its wallet without a hand-written message prefix.
/// Work that leaves the task (`spawn_blocking` for the pipelined prove) re-enters the span
/// explicitly.
pub async fn spawn(
    cfg: ActorConfig,
) -> anyhow::Result<(WalletHandle, tokio::task::JoinHandle<()>)> {
    use tracing::Instrument as _;
    let span = tracing::info_span!("wallet", name = %cfg.name);
    spawn_inner(cfg).instrument(span).await
}

async fn spawn_inner(
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
    ensure_dir_writable(&cfg.engine_dir)
        .with_context(|| format!("wallet '{}' data directory is not usable", cfg.name))?;

    // Apply the configured external transparent gap limit only for transparent-enabled wallets, so
    // shielded-only wallets keep librustzcash's default and are completely unaffected.
    let db_data = open::init_dbs_with_gap_limit(
        cfg.network,
        &cfg.engine_dir,
        cfg.transparent_enabled.then_some(cfg.transparent_gap_limit),
    )?;
    if cfg.transparent_enabled {
        // (The "transparent receiving enabled" info line - including the effective recovery
        // horizon - is emitted below, once the account is resolved: the horizon is anchored at
        // the account default address's frontier, which needs the account's viewing key.)
        // A wide window is a per-receive cost, not just a restore-scan bound: librustzcash's gap
        // maintenance re-derives the whole window every time a transparent receive is recorded
        // (see `config::TRANSPARENT_GAP_LIMIT_SEVERE`). The width stays the operator's choice
        // (never a startup failure), but past the severe bound the cost is a near-certain
        // stalled restore, so it logs at error level - the 0.5.1-rc2 field stall ran 71000.
        if cfg.transparent_gap_limit > crate::config::TRANSPARENT_GAP_LIMIT_SEVERE {
            error!(
                "transparent_gap_limit = {} will effectively STALL restores and slow every \
                 incoming transparent payment: recording one transparent receive re-derives the \
                 entire gap window (roughly {}s of address derivation per received UTXO, \
                 repeated per output of a multi-output transaction - a restore that discovers \
                 dozens of UTXOs grinds for hours on one core with no log output). Use a small \
                 gap limit plus [pools] transparent_initial_scan (a one-time pre-exposure with \
                 no per-receive cost) for deep restore coverage instead. Starting anyway.",
                cfg.transparent_gap_limit,
                cfg.transparent_gap_limit / 1200
            );
        } else if cfg.transparent_gap_limit > crate::config::TRANSPARENT_GAP_LIMIT_COSTLY {
            warn!(
                "transparent_gap_limit = {} is unusually large: every transparent receive \
                 recorded by the scan re-derives the entire gap window (roughly {}s of address \
                 derivation per received UTXO, repeated per output of a multi-output \
                 transaction). Prefer a small gap limit plus [pools] transparent_initial_scan \
                 for deep restore coverage.",
                cfg.transparent_gap_limit,
                cfg.transparent_gap_limit / 1200
            );
        }
    }
    let db_cache = open::open_fsblockdb(&cfg.engine_dir)?;
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
                // What can rebuild the account from `keys.toml` alone: the seed for a spending
                // wallet, or the pinned UFVK for a watch-only one. The pin is the same key
                // `init --ufvk` imported and the same one every startup verifies the account
                // against, and the birthday sits beside it, so a view-only rebuild needs
                // nothing the file does not already hold. Only a `keys.toml` written before the
                // pin existed (and never backfilled by a daemon start) is genuinely
                // unrebuildable.
                let bootstrap_key = if st.has_seed() {
                    Some(BootstrapKey::Seed)
                } else {
                    match st.pinned_ufvk() {
                        Some(pin) => Some(BootstrapKey::Ufvk(Box::new(
                            UnifiedFullViewingKey::decode(&cfg.network, pin).map_err(|e| {
                                anyhow!(
                                    "wallet '{}' has an empty data directory and the UFVK \
                                     pinned in keys.toml does not decode on {}: {e}. Recreate \
                                     it with `zecd init --ufvk`.",
                                    cfg.name,
                                    cfg.network.name()
                                )
                            })?,
                        ))),
                        None => None,
                    }
                };
                let Some(bootstrap_key) = bootstrap_key else {
                    // No seed and no pin: nothing on disk can rebuild a viewable account.
                    return Err(anyhow!(
                        "wallet '{}' has an empty data directory, and keys.toml holds neither a \
                         spending seed nor a pinned viewing key (a watch-only keys.toml written \
                         before the pin existed): it cannot be rebuilt. Recreate it with \
                         `zecd init --ufvk`.",
                        cfg.name
                    ));
                };
                if !cfg.bootstrap {
                    return Err(anyhow!(
                        "wallet '{}' has no account in {}; run `zecd init`, or enable \
                         [keys] bootstrap_from_keys to rebuild the data directory from keys.toml.",
                        cfg.name,
                        open::data_db_path(&cfg.engine_dir).display()
                    ));
                }
                let watch_only = matches!(bootstrap_key, BootstrapKey::Ufvk(_));
                info!(
                    "empty data directory with keys.toml present: rebuilding the {} account \
                     from keys.toml (birthday {}){}",
                    if watch_only {
                        "watch-only (pinned UFVK)"
                    } else {
                        "spending (seed)"
                    },
                    u32::from(st.birthday),
                    match (watch_only, encrypted) {
                        // A view-only rebuild needs no secret, so it proceeds as soon as the
                        // upstream is reachable.
                        (true, _) => "",
                        (false, true) =>
                            " once the seed is available (call walletpassphrase to unlock)",
                        (false, false) => " once the seed is available",
                    }
                );
                (None, None, watch_only, Some((st.birthday, bootstrap_key)))
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

    // The restore floor's default-address anchor (see [`recovery_horizon_for`]): resolvable now
    // for a wallet that already has an account; a bootstrap wallet fills it in at adoption.
    let transparent_default_frontier = match account_id {
        Some(id) if cfg.transparent_enabled => default_transparent_frontier(&db_data, id),
        _ => None,
    };
    if cfg.transparent_enabled {
        // Surface the transparent receiving config for operator auditing of restore coverage:
        // a stateless rebuild rediscovers transparent funds only below the recovery horizon
        // (or chained past it by funding).
        info!(
            "transparent receiving enabled (default_address={}, external_gap_limit={}, \
             initial_scan={}, recovery_horizon={})",
            cfg.transparent_default,
            cfg.transparent_gap_limit,
            cfg.transparent_initial_scan,
            recovery_horizon_for(
                cfg.transparent_initial_scan,
                transparent_default_frontier,
                cfg.transparent_gap_limit
            )
        );
    }

    // Determine the wallet's encryption mode, and for unencrypted wallets optionally decrypt
    // the seed up-front for unattended sending. An encrypted wallet has no passphrase at rest,
    // so it cannot auto-unlock - it starts locked and requires `walletpassphrase` (matching
    // Bitcoin Core's encrypted-wallet behavior). A watch-only wallet has no seed anywhere, so
    // the whole unlock machinery is moot for it.
    let birthday = u32::from(st.birthday);
    let mut seed = SeedKeeper::locked();
    if watch_only {
        info!(
            "watch-only wallet (imported UFVK): balances, history, and addresses are \
             available; spending and wallet-encryption RPCs are disabled"
        );
    } else if encrypted {
        info!(
            "wallet is passphrase-encrypted; it starts locked - call walletpassphrase to unlock for sending");
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
                        warn!(
                            target: "zecd::audit",
                            "auto-unlocked an unencrypted seed at startup: spend authority is \
                             resident in memory without a passphrase. Use `zecd init --encrypt` for \
                             the passphrase model if unattended spend authority is not intended");
                    }
                    Ok(None) => {}
                    Err(e) => warn!("could not decrypt seed at startup: {e}"),
                }
            }
        } else {
            warn!(
                "auto_unlock is set but no age identity configured; sending will require walletpassphrase");
        }
    } else {
        // An identity-encrypted wallet with auto_unlock=false is a dead end for sending:
        // it starts locked, and walletpassphrase on a non-passphrase wallet is -15 (like
        // bitcoind's unencrypted wallets) - there is no RPC that can unlock it. Reads still
        // work, so don't refuse to start; warn loudly instead.
        warn!(
            "auto_unlock=false on an identity-encrypted wallet: sends will fail (-13) and \
             walletpassphrase cannot unlock it (-15). Enable auto_unlock, or re-create the wallet \
             passphrase-encrypted with `zecd init --encrypt` (then walletpassphrase unlocks)."
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
        engine_dir: cfg.engine_dir.clone(),
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
        transparent_gap_limit: cfg.transparent_gap_limit,
        transparent_initial_scan: cfg.transparent_initial_scan,
        transparent_allow_beyond_recovery_window: cfg.transparent_allow_beyond_recovery_window,
        transparent_gap_warn_threshold: cfg.transparent_gap_warn_threshold,
        transparent_scripts: None,
        transparent_set_dirty: true,
        transparent_unspent: None,
        transparent_unspent_dirty: true,
        transparent_preexposed: false,
        transparent_preexpose: None,
        transparent_frontier: None,
        transparent_default_frontier,
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
        unsupported_upgrades: Vec::new(),
        last_sync_error: None,
        sync_error_streak: 0,
        sync_halted: false,
        force_sync: false,
        enhance_satisfied: std::collections::BTreeSet::new(),
        enhance_progress: None,
        shutdown: cfg.shutdown,
    };

    // `tokio::spawn` does not inherit the caller's span, so re-attach the wallet span the
    // setup is running under - it is what keeps every actor-lifetime event wallet-attributed.
    let task = {
        use tracing::Instrument as _;
        tokio::spawn(actor.run().instrument(tracing::Span::current()))
    };

    Ok((
        make_handle(
            cfg.name,
            cfg.engine_dir,
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

/// The reconnect deadline after a disconnect: `now + backoff.next_delay()`, advancing the backoff
/// exactly once. [`WalletActor::mark_disconnected`] uses this so every post-connection failure
/// (tip refresh, sync error, a stale-client operation) is paced with the same exponential +
/// jittered backoff a failed dial already gets, instead of leaving `reconnect_at` in the past and
/// letting the idle loop reconnect immediately into the same failure. The returned deadline is
/// never in the past (`next_delay` is non-negative), which is the property that breaks the tight
/// loop; the sync-error path additionally floors it at [`SYNC_ERROR_RETRY_INTERVAL`]. Factored out
/// so the pacing is unit-testable without standing up a full actor.
fn reconnect_after_backoff(now: Instant, backoff: &mut Backoff) -> Instant {
    now + backoff.next_delay()
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

/// zcashd's refusal (`-4`, message shape included) for a transparent funding source under a
/// policy that does not permit revealing the sender. Shared by the synchronous `z_sendmany`
/// pre-check and the actor's authoritative re-check so the two can't drift.
pub(crate) fn insufficient_privacy_for_transparent_sender(privacy: SendPrivacy) -> RpcError {
    RpcError::wallet(format!(
        "Insufficient privacy policy to allow transparent sender: {} does not permit funding a \
         send from transparent UTXOs (which reveals the sender's addresses and amounts). Use \
         privacyPolicy \"AllowRevealedSenders\" or weaker to allow this transaction to proceed.",
        privacy.policy_name()
    ))
}

/// zcashd's refusal (`-4`) for a transparent recipient paid *from* transparent funds - a fully
/// transparent transaction - under any policy short of `AllowFullyTransparent`. Shared by the
/// synchronous `z_sendmany` pre-check and the actor's authoritative re-check.
pub(crate) fn insufficient_privacy_for_fully_transparent() -> RpcError {
    RpcError::wallet(
        "Insufficient privacy policy to allow a transparent recipient paid from transparent \
         funds (a fully transparent transaction). Use privacyPolicy \"AllowFullyTransparent\" \
         or \"NoPrivacy\" to allow this transaction to proceed.",
    )
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

/// Build, sign, and record a **fully transparent** transaction from an already-fixed input set:
/// `selected` UTXOs in, `recipients` plus an optional pre-resolved transparent `change` output
/// out, balancing at exactly `fee_amount` (the `Builder` rejects a mismatch). This is the shared
/// core of `do_send_transparent` (which selects greedily to cover an amount and routes change to
/// the internal chain) and the t→t arm of `z_mergetoaddress` (which fixes the input set at
/// propose time and pays out `inputs - fee` with **no** change) - single-sourcing the signing
/// (USK-derived key at each input address's recorded `(scope, index)`) and the
/// `store_transactions_to_be_sent` recording (which locks the spent UTXOs and keeps the raw
/// bytes for the rebroadcast loop). Must run under `block_in_place`; broadcasting is the
/// caller's job.
#[allow(clippy::too_many_arguments)]
fn build_signed_transparent_tx(
    db: &mut WriteDb,
    net: ZNetwork,
    target_height: TargetHeight,
    usk: &zcash_keys::keys::UnifiedSpendingKey,
    account_id: AccountUuid,
    selected: &[WalletTransparentOutput<AccountUuid>],
    recipients: &[(TransparentAddress, Zatoshis)],
    change: Option<(TransparentAddress, Zatoshis)>,
    fee_amount: Zatoshis,
    prover: &LocalTxProver,
) -> Result<(TxId, Vec<u8>), RpcError> {
    use rand::rngs::OsRng;

    let fee_rule = Zip317FeeRule::standard();
    let mut builder = Builder::new(
        net,
        BlockHeight::from(target_height),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            // Upstream `BuildConfig::Standard` now carries `ironwood_anchor` unconditionally;
            // this is a transparent-only send (no shielded spends), so there's no anchor.
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );

    // Add and key each transparent input. The signing key is derived from the USK transparent
    // component at the input address's recorded `(scope, index)`; the builder matches each
    // input to its key by public key.
    let mut signing_set = TransparentSigningSet::new();
    let mut spent: Vec<zcash_transparent::bundle::OutPoint> = Vec::new();
    let acct_priv = usk.transparent();
    for utxo in selected {
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
        let sk = acct_priv
            .derive_secret_key(scope, index)
            .map_err(|e| RpcError::wallet(format!("transparent key derivation failed: {e}")))?;
        let pubkey = signing_set.add_key(sk);
        builder
            .add_transparent_p2pkh_input(pubkey, utxo.outpoint().clone(), utxo.txout().clone())
            .map_err(|e| RpcError::wallet(format!("add transparent input: {e}")))?;
        spent.push(utxo.outpoint().clone());
    }

    // Recipient outputs (vout 0..n), then the transparent change output (if any).
    for (addr, amt) in recipients {
        builder
            .add_transparent_output(addr, *amt)
            .map_err(|e| RpcError::wallet(format!("add transparent output: {e}")))?;
    }
    if let Some((change_addr, change_val)) = &change {
        builder
            .add_transparent_output(change_addr, *change_val)
            .map_err(|e| RpcError::wallet(format!("add change output: {e}")))?;
    }

    let result = builder
        .build(&signing_set, &[], &[], OsRng, prover, prover, &fee_rule)
        .map_err(|e| RpcError::wallet(format!("transparent transaction build failed: {e}")))?;
    let tx = result.transaction();
    let txid = tx.txid();
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| RpcError::misc(format!("failed to serialize transaction: {e}")))?;

    // Record the send so the spent UTXOs are locked (no double-spend), the raw tx rides the
    // rebroadcast loop, and history reflects the outgoing payment. A change output is recorded
    // as an external transparent output to our own address; the receive scan re-adds it as a
    // spendable UTXO once mined.
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
    if let Some((change_addr, change_val)) = change {
        outputs.push(SentTransactionOutput::from_parts(
            recipients.len(),
            Recipient::External {
                recipient_address: Address::Transparent(change_addr).to_zcash_address(&net),
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
}

/// The most transparent inputs one `z_mergetoaddress` call may select, mirroring librustzcash's
/// shielding block-space bound (`shielding_max_inputs` at its default 10% of the 2,000,000-byte
/// block over the ~150-byte P2PKH input size). Both the caller's `transparent_limit` and this
/// cap apply; zcashd's `transparent_limit = 0` means "as many as will fit", which is this.
const MERGE_MAX_TRANSPARENT_INPUTS: usize = (2_000_000 * 10 / 100) / 150;

/// The exact ZIP-317 fee for a fully-transparent merge: `n_in` standard P2PKH inputs and ONE
/// transparent output of `out_bytes` serialized bytes, no change. The logical action count is
/// `max(n_in, ceil(out_bytes / p2pkh_out_size))`, floored at `grace`, times `marginal` - the
/// same arithmetic as `select_transparent_inputs`'s fee closure, which the transaction
/// `Builder` requires to balance exactly.
fn merge_transparent_fee(
    n_in: usize,
    out_bytes: usize,
    p2pkh_out_size: usize,
    marginal: u64,
    grace: usize,
) -> u64 {
    marginal * grace.max(n_in.max(out_bytes.div_ceil(p2pkh_out_size))) as u64
}

/// Resolve the output pool a shielded `z_mergetoaddress` destination pays into, mirroring
/// librustzcash's `resolve_shielded_destination`: an Orchard receiver takes delivery precedence
/// and lands in the Ironwood pool once NU6.3 is active (an Orchard receiver holds Ironwood
/// notes post-activation), else the Orchard pool; a Sapling-only recipient lands in Sapling.
/// The caller has already peeled off bare transparent destinations.
fn merge_shielded_destination_pool(
    dest: &Address,
    ironwood_active: bool,
) -> Result<PoolType, RpcError> {
    if crate::address::has_orchard_receiver(dest) {
        Ok(if ironwood_active {
            PoolType::IRONWOOD
        } else {
            PoolType::ORCHARD
        })
    } else if crate::address::has_shielded_receiver(dest) {
        Ok(PoolType::SAPLING)
    } else {
        Err(RpcError::invalid_parameter(
            "Invalid parameter, toaddress has no shielded receiver",
        ))
    }
}

/// The per-bundle output/action counts a merge's ZIP-317 fee must price, mirroring
/// librustzcash's `propose_send_max` (padded `BundleType::DEFAULT`, per-height bundle
/// versions): Sapling outputs via `num_outputs(spends, requested)`, Orchard and Ironwood
/// actions via `transactional_action_count(spends, outputs)` on their respective bundle
/// versions. `dest_pool` decides which bundle carries the single payment output; spends are
/// the selected notes per pool (all zero for a transparent-source merge).
fn merge_action_counts(
    net: &ZNetwork,
    target_height: TargetHeight,
    dest_pool: PoolType,
    sapling_spends: usize,
    orchard_spends: usize,
    ironwood_spends: usize,
) -> Result<(usize, usize, usize), RpcError> {
    // The `num_actions` calls are librustzcash's own `transactional_action_count` inlined (it is
    // crate-private there): the padded default bundle's action count for the given spends and
    // outputs under that bundle version's flags. The builder enforces an exact balance against
    // the fee computed from these counts, so they must match its configuration.
    let branch = BranchId::for_height(net, BlockHeight::from(target_height));
    let sapling_out = sapling::builder::BundleType::DEFAULT
        .num_outputs(sapling_spends, usize::from(dest_pool == PoolType::SAPLING))
        .map_err(|e| RpcError::wallet(format!("sapling bundle shape: {e}")))?;
    let orchard_version = bundle_version_for_branch(branch, orchard::ValuePool::Orchard)
        .unwrap_or(orchard::bundle::BundleVersion::orchard_v2());
    let orchard_act = orchard::builder::BundleType::DEFAULT
        .num_actions(
            orchard_version.default_flags(),
            orchard_spends,
            usize::from(dest_pool == PoolType::ORCHARD),
        )
        .map_err(|e| RpcError::wallet(format!("orchard bundle shape: {e}")))?;
    // The Ironwood pool has no bundle version before NU6.3; an empty bundle counts zero actions
    // under any version, so the fallback only matters for the count math, never for consensus.
    let ironwood_version = bundle_version_for_branch(branch, orchard::ValuePool::Ironwood)
        .unwrap_or(orchard::bundle::BundleVersion::ironwood_v3());
    let ironwood_act = orchard::builder::BundleType::DEFAULT
        .num_actions(
            ironwood_version.default_flags(),
            ironwood_spends,
            usize::from(dest_pool == PoolType::IRONWOOD),
        )
        .map_err(|e| RpcError::wallet(format!("ironwood bundle shape: {e}")))?;
    Ok((sapling_out, orchard_act, ironwood_act))
}

/// A [`NoteRetention`] that keeps everything: the merge's manual selection already truncated
/// the note set, so `into_vec` must convert it losslessly to the unified note shape
/// [`ShieldedInputs`] carries.
struct RetainAllNotes;

impl<NoteRef> NoteRetention<NoteRef> for RetainAllNotes {
    fn should_retain_sapling(
        &self,
        _: &zcash_client_backend::wallet::ReceivedNote<NoteRef, sapling::Note>,
    ) -> bool {
        true
    }
    fn should_retain_orchard(
        &self,
        _: &zcash_client_backend::wallet::ReceivedNote<NoteRef, orchard::note::Note>,
    ) -> bool {
        true
    }
    fn should_retain_ironwood(
        &self,
        _: &zcash_client_backend::wallet::ReceivedNote<NoteRef, orchard::note::Note>,
    ) -> bool {
        true
    }
}

/// Map a `create_proposed_transactions` failure on a merge plan onto the RPC error surface:
/// shortfalls (a selected input spent by a racing send) are `-6`, everything else `-4`.
fn classify_merge_execute_err<E: std::fmt::Display>(e: E) -> RpcError {
    let s = e.to_string();
    if s.to_lowercase().contains("insufficient") {
        RpcError::insufficient_funds(s)
    } else {
        RpcError::wallet(s)
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

/// The librustzcash [`SpendPolicy`] a send's funding source implies. A transparent source
/// permits **no** shielded pools (an empty set): one source per send, so a shortfall is a `-6`
/// insufficient-funds on the named source, never a silent top-up from shielded notes (and
/// vice versa - the default policy never pulls in transparent UTXOs). Coinbase is excluded
/// explicitly (it is also the constructor default): consensus requires a transparent-coinbase
/// spend to have an empty `vout`, and coinbase funds stay `z_shieldcoinbase`'s alone.
fn spend_policy_for_source(source: SendSource) -> SpendPolicy {
    match source {
        SendSource::Unspecified | SendSource::Shielded => SpendPolicy::default(),
        SendSource::Transparent(None) => SpendPolicy::shielded_pools(std::iter::empty())
            .with_transparent(
                TransparentSpendPolicy::any_account_addr()
                    .with_coinbase(CoinbasePolicy::NonCoinbase),
            ),
        SendSource::Transparent(Some(t)) => SpendPolicy::shielded_pools(std::iter::empty())
            .with_transparent(
                TransparentSpendPolicy::from_one_address(t)
                    .with_coinbase(CoinbasePolicy::NonCoinbase),
            ),
    }
}

/// Log an internal upstream (zebra) connection/transport failure server-side and return a
/// generic client-facing `RpcError`. `detail` (the raw error) carries
/// infrastructure fingerprints - the configured zebra host:port, the cookie-file path from the
/// connection context - which must never reach the RPC client. Only the operator's logs see it;
/// the client gets `client_msg`, a fixed generic string. The blanket `From<anyhow::Error>` impl
/// already scrubs errors that flow through `?`, but these `RpcError::misc(format!(... {e}))`
/// sites format the error directly, bypassing that funnel, so they scrub here.
fn upstream_error(detail: impl std::fmt::Display, client_msg: &str) -> RpcError {
    warn!("{client_msg}: {detail}");
    RpcError::misc(client_msg)
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

/// The `-8` returned when a transparent address is requested on a wallet that does not enable
/// transparent receiving. Shared by every entry point that can derive one (`getnewaddress`,
/// `z_getaddressforaccount`) so the remedy is worded once.
fn transparent_not_enabled() -> RpcError {
    RpcError::invalid_parameter(
        "transparent addresses are not enabled on this wallet (set [pools] transparent = true)",
    )
}

/// A diversifier index viewed as a BIP 44 **non-hardened child index** - the index a transparent
/// receiver is derived at. `None` when the value does not fit that range (`>= 2^31`, i.e. the
/// hardened half), which no transparent address can be derived at.
fn transparent_child_index(j: DiversifierIndex) -> Option<u32> {
    u32::try_from(u128::from(j))
        .ok()
        .filter(|i| *i < (1u32 << 31))
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

/// Recoverable address slots remaining under the stateless-restore recovery horizon
/// (`transparent_initial_scan + transparent_gap_limit`) after issuing the address at external
/// child index `index`. The horizon is the floor-anchored half of restore coverage: a from-seed
/// restore pre-exposes `0..initial_scan` and its gap lookahead extends `gap_limit` past that
/// frontier, so indices below the horizon are recoverable regardless of funding. (Funding then
/// slides the frontier further - that half is librustzcash's funded-anchored window and is
/// accounted separately via `GapMetadata::InGap`.) Counting the horizon alongside the window in
/// `warn_if_gap_low` is load-bearing noise control: without it, a wallet configured the intended
/// A18 way (small gap limit, large initial scan) warned "recovery window nearly exhausted" on
/// issuance it could in fact recover - noise that in the field pushed an operator to silence it
/// by raising `transparent_gap_limit` above `transparent_initial_scan`, the configuration whose
/// per-receive window regeneration stalls restores (see `config::TRANSPARENT_GAP_LIMIT_SEVERE`).
fn horizon_slots_remaining(horizon: u32, index: u32) -> u32 {
    horizon.saturating_sub(index.saturating_add(1))
}

/// The stateless-restore recovery horizon: external indices strictly below it are recoverable on
/// a from-seed restore regardless of funding. It is `gap_limit` past the **restore floor** - the
/// frontier a fresh restore of the seed starts with, which is the larger of the pre-exposed
/// `transparent_initial_scan` window and the account default address's frontier
/// (`default_frontier` = default-address child index + 1; `None` when unknown).
///
/// The default-address anchor is what makes the horizon exact rather than conservative-but-wrong:
/// account creation exposes the default Unified Address's transparent receiver at a per-seed
/// index `d`, so *every* restore's matcher starts its gap lookahead at `d + 1` (and matches the
/// pre-generated rows `0..=d` too), covering `0 .. max(initial_scan, d + 1) + gap_limit`
/// contiguously on day one. Without the anchor, a seed whose default address lands at `d >=
/// gap_limit` reported a fresh restore as beyond its own horizon (`restorable: false`) - the
/// CI-observed shape that motivated this function.
fn recovery_horizon_for(initial_scan: u32, default_frontier: Option<u32>, gap_limit: u32) -> u32 {
    initial_scan
        .max(default_frontier.unwrap_or(0))
        .saturating_add(gap_limit)
}

/// One past the account default address's transparent child index - the frontier a fresh
/// from-seed restore of this account starts with (see
/// [`WalletActor::transparent_default_frontier`]). Derived exactly as account creation does:
/// the first diversifier index valid for every receiver of the account's UIVK
/// (`UnifiedAddressRequest::AllAvailableKeys`). `None` when the account is unavailable, the
/// default address carries no transparent receiver, or its index is out of the non-hardened
/// range (not derivable as a transparent child).
fn default_transparent_frontier(
    db_data: &crate::wallet::open::WriteDb,
    account_id: AccountUuid,
) -> Option<u32> {
    use zcash_keys::keys::UnifiedAddressRequest;
    let account = db_data.get_account(account_id).ok()??;
    let (ua, d_idx) = account
        .uivk()
        .find_address(
            DiversifierIndex::new(),
            UnifiedAddressRequest::AllAvailableKeys,
        )
        .ok()?;
    ua.transparent()?;
    transparent_child_index(d_idx).map(|i| i.saturating_add(1))
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
            warn!("initial upstream connect failed: {e}");
        }
        if self.client.is_some() {
            if let Err(e) = self.refresh_tip().await {
                warn!("initial tip refresh failed: {e}");
                self.client = None;
            }
        }
        self.update_status();

        let mut more_work = true;
        loop {
            // Exit between sync batches once shutdown is signalled, so Ctrl-C/`stop` doesn't
            // wait out a long catch-up scan and the DB connection is dropped cleanly.
            if *self.shutdown.borrow() {
                info!("wallet actor shutting down");
                return;
            }
            // Relock an encrypted wallet whose passphrase timeout has elapsed. Checked every
            // iteration (between sync batches) so the seed doesn't linger long past expiry; the
            // `select!` branch below handles the idle case, and `do_send` has a hard backstop.
            self.relock_if_expired();
            // An explicit `waitforsync` nudge counts as work to do, so the pass runs now rather
            // than after up to a full `sync_interval` of idling. Consumed here so one nudge
            // buys exactly one pass.
            if std::mem::take(&mut self.force_sync) {
                more_work = true;
            }
            // A halted wallet serves commands and reads but never re-attempts the scan: the
            // failure that halted it cannot succeed on retry (see `sync_halted`). Clearing
            // `more_work` every pass keeps the loop parked in the `select!` below rather than
            // spinning, and still lets a command wake it.
            if self.sync_halted {
                more_work = false;
            }
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
                        // A successful pass ends any failure streak (see `note_sync_error`).
                        self.last_sync_error = None;
                        self.sync_error_streak = 0;
                        if worked {
                            more_work = true;
                            // New blocks were scanned, which may add or re-satisfy enhancement
                            // requests - start the next drain from a clean slate. The heartbeat
                            // resets with it (its serviced count is `enhance_satisfied.len()`).
                            self.enhance_satisfied.clear();
                            self.enhance_progress = None;
                        } else {
                            // Caught up: give any unmined wallet txs another shot at the mempool,
                            // pull the full data (memos, …) for transactions seen only as compact
                            // blocks, and (re)subscribe to incoming mempool txs for 0-conf visibility.
                            // (Transparent receives are discovered by the block scan itself - see
                            // `sync_step` - and at 0-conf by the mempool path below, on every
                            // supported backend.)
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
                        // `mark_disconnected` already paced the reconnect through the backoff.
                        // A *persistent* sync error (e.g. an unrecoverable reorg whose rewind
                        // target has no checkpoint) would otherwise spin: the reconnect succeeds
                        // (the upstream is healthy) and the very next batch re-hits the same error
                        // - hundreds of times a second, pegging a core and flooding the log. Floor
                        // the backoff-paced deadline at a fixed minimum so even a base-delay
                        // backoff (or a near-zero jitter draw) still caps this to one attempt per
                        // interval; a transient error just costs this small delay.
                        //
                        // `note_sync_error` tracks the failure streak and appends recovery
                        // guidance when the failure is diagnosable: an unsupported network
                        // upgrade (update zecd / report on the forum) or a persistent
                        // wallet-database apply error (`zecd rescan`).
                        // An unrecoverable reorg is the one sync failure retrying cannot fix, so
                        // it stops the scan instead of pacing it forever. Logged once, at ERROR,
                        // naming the operator action; the reason also rides `mark_disconnected`
                        // onto `/readyz` and `/status`.
                        if !self.sync_halted && sync_failure_is_terminal(&e) {
                            self.sync_halted = true;
                            error!(
                                "{e}; sync is HALTED for this wallet - retrying cannot \
                                 remove the conflicting block. Stop the daemon and run `zecd \
                                 rescan --wallet {name}` to rebuild the wallet database from the \
                                 seed (keys.toml is kept) and resync from the wallet birthday. \
                                 Reads, address issuance and the rest of the RPC surface keep \
                                 working meanwhile; balances and history are frozen at the last \
                                 scanned block",
                                name = self.name
                            );
                        }
                        let reason = self.note_sync_error(&e);
                        self.mark_disconnected(reason);
                        self.reconnect_at = self
                            .reconnect_at
                            .max(sync_error_retry_deadline(Instant::now()));
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
                            info!("wallet actor shutting down");
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
                                // One WARN per outage (the first failed attempt; the disconnect
                                // itself already warned when the outage began that way), then
                                // the paced retries drop to DEBUG so a long outage doesn't
                                // stream WARNs - recovery logs its own "connected to" INFO.
                                let attempt = self.backoff.attempt();
                                let delay = self.backoff.next_delay();
                                self.reconnect_at = Instant::now() + delay;
                                if attempt == 0 {
                                    warn!(
                                        delay_ms = delay.as_millis() as u64,
                                        "reconnect failed: {e}; retrying with backoff \
                                         (further attempts log at debug until the connection \
                                         recovers)"
                                    );
                                } else {
                                    tracing::debug!(
                                        attempt = attempt + 1,
                                        delay_ms = delay.as_millis() as u64,
                                        "reconnect failed: {e}"
                                    );
                                }
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
                            error!("mempool tx handler panicked; the actor continues");
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
                        tracing::debug!("mempool stream error: {e}");
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
                    "wallet command handler panicked; the actor continues and the command \
                     failed (this is a bug - please report it)"
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
                    "wallet sync batch panicked; the actor continues (this is a bug - \
                     please report it)"
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
                error!("transaction enhancement panicked; the actor continues");
                false
            }
        }
    }

    /// Drop the upstream client and, if the connection had been announced (its "connected"
    /// line was logged), warn that it was lost with the reason. Gating on `connected_logged`
    /// keeps disconnects matched to connects: a client dropped before it ever came up (a
    /// failed dial / health check) is reported by the connect path instead, not here.
    ///
    /// Every disconnect also paces the next reconnect through the backoff. A failure *after* a
    /// successful connect (a tip refresh against a reachable-but-degraded upstream, a sync
    /// error, a stale-client operation) would otherwise leave `reconnect_at` in the past, so the
    /// next idle tick would reconnect immediately and re-hit the same failure - a tight loop that
    /// pegs a core and floods the log. Advancing the backoff here gives every post-connection
    /// failure the same exponential + jittered pacing a failed dial already gets. (The
    /// dial-failure path sets `reconnect_at` itself and does *not* route through here - it drops
    /// the client directly - so a single failed dial still paces exactly once.)
    fn mark_disconnected(&mut self, reason: impl std::fmt::Display) {
        self.client = None;
        self.reconnect_at = reconnect_after_backoff(Instant::now(), &mut self.backoff);
        if std::mem::take(&mut self.connected_logged) {
            warn!("disconnected from {}: {reason}", self.server.describe());
        }
    }

    /// Announce, once per connection, every upstream-reported network upgrade this build does
    /// not recognize. An *active* one is an error - the scan will fail at (or is already
    /// failing past) its activation, and nothing but a newer zecd fixes that - while a
    /// *pending* one is the advance warning that lets an operator update before the network
    /// switches, instead of discovering the gap later as a stuck sync loop.
    fn log_unsupported_upgrades(&self) {
        for u in &self.unsupported_upgrades {
            let name = sanitize_upstream_msg(&u.name);
            let height = u
                .activation_height
                .map(|h| h.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            if u.active {
                error!(
                    "the upstream chain has activated network upgrade '{name}' (consensus \
                     branch 0x{:08x}, activation height {height}) which this zecd build does \
                     not support: block scanning cannot proceed past the activation. \
                     {UPGRADE_GUIDANCE}",
                    u.branch_id
                );
            } else {
                warn!(
                    "the upstream reports network upgrade '{name}' (consensus branch \
                     0x{:08x}) activating at height {height}, which this zecd build does not \
                     support: syncing will stop there. {UPGRADE_GUIDANCE}",
                    u.branch_id
                );
            }
        }
    }

    /// Record a failed sync pass and build the disconnect reason for it: the raw error, plus
    /// [`sync_failure_hint`]'s recovery guidance when the failure is diagnosable (an
    /// unsupported network upgrade, or a persistently-repeating wallet-database error). The
    /// streak only counts consecutive passes failing with the *same* display text - a changing
    /// error means the wallet is moving (e.g. through distinct reorg stages), not stuck.
    fn note_sync_error(&mut self, e: &anyhow::Error) -> String {
        let msg = format!("sync error: {e}");
        if self.last_sync_error.as_deref() == Some(msg.as_str()) {
            self.sync_error_streak = self.sync_error_streak.saturating_add(1);
        } else {
            self.last_sync_error = Some(msg.clone());
            self.sync_error_streak = 1;
        }
        // An upgrade is "in play" once active per the upstream, or once its announced
        // activation height is at/below the tip we've seen (the status is a snapshot from
        // connect time and can go stale across the boundary).
        let upgrade = self.unsupported_upgrades.iter().find(|u| {
            u.active
                || u.activation_height
                    .zip(self.tip_height)
                    .is_some_and(|(h, tip)| h <= tip)
        });
        let apply_side = e.downcast_ref::<engine::WalletApplyError>().is_some();
        match sync_failure_hint(apply_side, self.sync_error_streak, &self.name, upgrade) {
            Some(hint) => format!("{msg} ({hint})"),
            None => msg,
        }
    }

    /// Connect to the upstream zebrad endpoint. On success, store the client (after the
    /// subtree-root health check). On failure, leave `self.client` as `None` and return the
    /// error. The backoff is *not* reset here: a connect that immediately fails post-connection
    /// (e.g. the first tip refresh fails against a reachable-but-degraded upstream) must keep the
    /// backoff growing, so the reset lives on the first *successful* tip refresh instead.
    async fn connect(&mut self) -> anyhow::Result<()> {
        // Any open mempool stream belongs to the channel being replaced; drop it so it can't
        // pin the old connection alive. It is reopened on the next caught-up sync pass.
        self.mempool = None;
        let describe = self.server.describe();
        info!("connecting to {}", describe);
        let client = self.server.connect_timeout(self.connect_timeout).await?;
        self.client = Some(client);
        let client = self.client.as_mut().expect("just set");
        // A reachable-but-unhealthy upstream can still fail here; treat that as a failed connect.
        match prepare_client(
            client,
            &mut self.db_data,
            self.network,
            self.transparent_enabled,
            &mut self.subtree_roots_synced,
            PREPARE_TIMEOUT,
        )
        .await
        {
            Err(e) => {
                warn!("health check failed on {}: {e}", describe);
                self.client = None;
                return Err(e);
            }
            Ok(info) => {
                // Refresh the outdated-build detection from what this upstream reports and
                // announce any gap once per connection (a persistent apply failure reconnects
                // on the paced retry, so an active gap stays visible in the log alongside each
                // "sync error" it causes).
                self.unsupported_upgrades = crate::chain::unsupported_upgrades(&info);
                self.log_unsupported_upgrades();
            }
        }
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
                tracing::debug!("subscribed to the mempool stream");
                self.mempool = Some(stream);
            }
            Ok(Err(e)) => {
                tracing::debug!("mempool stream unavailable: {e}");
            }
            Err(_) => {
                tracing::debug!(
                    "mempool stream subscription timed out after {UNARY_RPC_TIMEOUT:?}"
                );
            }
        }
    }

    /// The enhancement backlog as `(count, lowest referenced height)`.
    ///
    /// The count is the serviceable transaction-data requests still pending in this drain - the
    /// backlog surfaced on `SyncStatus.pending_enhancements`. This is the work that remains
    /// *after* the block scan reaches the tip: compact blocks carry no memos, so each pending
    /// request is one full-transaction fetch + decrypt/store away from being served. Requests
    /// already attempted this drain (`enhance_satisfied`) and unsupported ones
    /// ([`is_serviceable_request`]) are excluded, so a clean drain converges to zero.
    ///
    /// The second element is what [`SyncStatus::enhanced_through`] is derived from: the lowest
    /// block height any still-pending request refers to, so every height strictly below it is
    /// known to be fully enhanced. A request refers to a height by way of
    /// [`enhancement_request_height`]; `None` means nothing pending refers to any height, and
    /// the whole scanned range is enhanced.
    ///
    /// Cost is bounded by [`ENHANCED_THROUGH_MAX_PROBE`]: resolving an `Enhancement`/`GetStatus`
    /// request to a height is a point query per request, and a post-restore drain can hold tens
    /// of thousands of them. Past that bound the height is reported as unknown (`Some(0)`,
    /// which floors the watermark) rather than paying a five-figure query count on every status
    /// update - a consumer waits for the backlog to come down instead, which is the same thing
    /// it would do anyway. The count itself is always exact; only the watermark degrades.
    fn enhancement_backlog(&self) -> (u64, Option<u32>) {
        let reqs = match self.db_data.transaction_data_requests() {
            Ok(reqs) => reqs,
            Err(e) => {
                // Best-effort for the count (observability), but the watermark must fail
                // closed: reporting "everything below X is enhanced" off a failed read could
                // let a consumer advance past a memo it never saw.
                tracing::debug!("reading transaction data requests: {e}");
                return (0, Some(0));
            }
        };
        let pending: Vec<_> = reqs
            .iter()
            .filter(|r| is_serviceable_request(r) && !self.enhance_satisfied.contains(r))
            .collect();
        let count = pending.len() as u64;
        if pending.is_empty() {
            return (0, None);
        }
        if pending.len() > ENHANCED_THROUGH_MAX_PROBE {
            return (count, Some(0));
        }
        // Requests referring to no mined height are skipped rather than treated as a zero
        // bound: an unmined transaction is above every mined height by construction (it can
        // only mine at a future one), so it cannot make an already-scanned height un-enhanced.
        // `min` over `Option` would get this backwards, since `None` sorts below `Some`.
        let lowest = pending
            .iter()
            .filter_map(|r| self.enhancement_request_height(r))
            .min();
        (count, lowest)
    }

    /// The block height a pending [`TransactionDataRequest`] refers to, or `None` when it refers
    /// to no mined height (an unmined transaction, which no height watermark can be below).
    ///
    /// `Enhancement`/`GetStatus` name a transaction, so the height is that transaction's;
    /// `TransactionsInvolvingAddress` names a range, so it is the range's start.
    fn enhancement_request_height(&self, req: &TransactionDataRequest) -> Option<u32> {
        match req {
            TransactionDataRequest::GetStatus(txid) | TransactionDataRequest::Enhancement(txid) => {
                self.db_data
                    .get_tx_height(*txid)
                    .ok()
                    .flatten()
                    .map(u32::from)
            }
            TransactionDataRequest::TransactionsInvolvingAddress(addr_req) => {
                Some(u32::from(addr_req.block_range_start()))
            } // Deliberately no catch-all arm: a new upstream request variant must stop this
              // compiling, so its height contribution is decided here rather than defaulting to
              // "bounds nothing" - which would silently let the watermark run past work the new
              // variant represents. Match `is_serviceable_request`, which faces the same choice.
        }
    }

    /// Emit an enhancement-drain progress heartbeat, throttled to one line per
    /// [`ENHANCE_LOG_INTERVAL`]. The serviced count is `enhance_satisfied.len()` (requests
    /// attempted this drain); `pending` is the serviceable backlog still in hand. Logged because
    /// the `pending_enhancements` *count* is a snapshot of a queue whose total size isn't knowable
    /// up front (servicing a request can enqueue successors), so a flat reading between polls does
    /// not distinguish steady progress from a stall - the heartbeat does.
    fn maybe_log_enhance_progress(&mut self, pending: usize) {
        let done = self.enhance_satisfied.len();
        let Some(progress) = self.enhance_progress.as_mut() else {
            // Drain just started: arm the throttle without logging, so short drains stay quiet.
            self.enhance_progress = Some(crate::progress::ProgressThrottle::new(
                ENHANCE_LOG_INTERVAL,
                done as u64,
            ));
            return;
        };
        if let Some(w) = progress.tick(done as u64) {
            info!(
                serviced = done,
                pending,
                elapsed_secs = w.elapsed_secs as u64,
                rate_per_sec = (w.rate * 10.0).round() / 10.0,
                "enhancement drain in progress"
            );
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
                warn!("reading transaction data requests: {e}");
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
        if pending.is_empty() {
            self.enhance_progress = None;
        } else {
            self.maybe_log_enhance_progress(pending.len());
        }
        let mut handled = 0usize;
        for req in &pending {
            // Bail promptly on Ctrl-C/`stop` rather than fetching out the rest of a long backlog.
            if *self.shutdown.borrow() {
                return false;
            }
            // Per-request visibility for a long drain, below DEBUG (a from-birthday restore
            // services tens of thousands of these).
            tracing::trace!(request = ?req, "servicing transaction data request");
            if let Err(e) = self.service_data_request(req, chain_tip).await {
                // A transport failure has already dropped the client (a DB-write error just ends
                // the batch); either way stop here and retry the remainder on the next pass rather
                // than spinning on a persistent failure.
                tracing::debug!("transaction enhancement aborted: {e}");
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
                // Check the address straight through to the chain tip, extending past the
                // request's own ~40-block windowed end - see [`tia_check_range`] for why (one
                // indexed zebra query replaces thousands of sequential window round trips per
                // address on a deep restore). `None` means nothing is checkable yet (a
                // spend-search request whose funding tx is still unmined): skip the query AND
                // the notification - notifying would claim a check that never ran (and the
                // backend's `as_of == block_range_end - 1` consistency check would reject any
                // honest height anyway, aborting the whole pass). The request stays in the DB
                // for a later pass; `enhance_step` marks it attempted for this drain, so it
                // can't spin the batch loop or pin the backlog count above zero.
                let Some((start, as_of)) = tia_check_range(
                    u32::from(addr_req.block_range_start()),
                    u32::from(chain_tip),
                ) else {
                    // Log the skip: an unserviceable spend-search is otherwise invisible, which
                    // makes "the wallet never found the spend" indistinguishable from "the
                    // request was never emitted" when reading a failing restore's logs.
                    use zcash_keys::encoding::AddressCodec as _;
                    tracing::debug!(
                        "TIA: skipping address={} - range starts at {}, past the tip {}",
                        addr_req.address().encode(&self.network),
                        u32::from(addr_req.block_range_start()),
                        u32::from(chain_tip),
                    );
                    return Ok(());
                };
                let address = addr_req.address().encode(&self.network);
                tracing::debug!("TIA: address-txid query addr={address} range={start}..={as_of}");
                let evidence = self
                    .fetch_transparent_tx_evidence(vec![address], start, as_of)
                    .await
                    .map_err(|e| anyhow!("{e}"))?;
                tracing::debug!(
                    "TIA: address-txid query returned {} item(s)",
                    evidence.len()
                );
                self.store_tx_evidence(evidence, chain_tip).await?;
                // Record the address as checked up to `as_of` (the inclusive end), whether or not
                // any txs were found, so the request converges instead of being re-emitted every
                // caught-up pass. The backend insists the notified height equal the request's
                // `block_range_end - 1`, so rebuild the request over the range actually checked
                // (`notify_address_checked` reads only the address and the heights, and the
                // extended claim is truthful - the query above covered the whole range).
                let TransactionDataRequest::TransactionsInvolvingAddress(checked) =
                    TransactionDataRequest::transactions_involving_address(
                        addr_req.address(),
                        addr_req.block_range_start(),
                        Some(BlockHeight::from_u32(as_of + 1)),
                        addr_req.request_at(),
                        addr_req.tx_status_filter().clone(),
                        addr_req.output_status_filter().clone(),
                    )
                else {
                    unreachable!("transactions_involving_address builds that variant");
                };
                self.db_data
                    .notify_address_checked(checked, BlockHeight::from_u32(as_of))?;
            }
        }
        Ok(())
    }

    /// Store every transaction named by a batch of [`TxEvidence`] (from a transparent
    /// address-history query): parse-or-fetch, `decrypt_and_store_transaction`, and run the
    /// transparent receive matcher. Shared by the TIA servicing arm and the offline-window sweep.
    ///
    /// The receive matcher runs belt-and-braces: librustzcash's `store_decrypted_tx` attributes
    /// transparent outputs against the `addresses` table itself on this line, but
    /// `record_tx_transparent_receives` is byte-for-byte the path the block scan and mempool use,
    /// and `put_received_transparent_utxo` is idempotent - so recording here guarantees a swept
    /// receive lands identically to one the block scan would have found.
    async fn store_tx_evidence(
        &mut self,
        evidence: Vec<TxEvidence>,
        chain_tip: BlockHeight,
    ) -> anyhow::Result<()> {
        for item in evidence {
            // The evidence can cover a whole restore's history for a heavily reused address,
            // so bail between fetches on Ctrl-C/`stop` rather than fetching it out. Callers
            // notify nothing on this error, so the request is simply re-serviced on the next
            // run; each already-stored tx is kept.
            if *self.shutdown.borrow() {
                return Err(anyhow!("shutdown during address check"));
            }
            let (tx, mined) = match item {
                // zebra: txid only - fetch the full tx before storing.
                TxEvidence::Txid(txid) => match self.fetch_full_tx(txid, chain_tip).await? {
                    Some(found) => found,
                    None => continue,
                },
                // lightwalletd: `GetTaddressTxids` already streamed the full raw tx - parse and
                // store it directly, no re-fetch.
                TxEvidence::Raw(raw) => {
                    let mined = raw.mined_height.map(BlockHeight::from_u32);
                    let tx = Transaction::read(
                        &raw.data[..],
                        BranchId::for_height(&self.network, mined.unwrap_or(chain_tip)),
                    )?;
                    (tx, mined)
                }
            };
            decrypt_and_store_transaction(&self.network, &mut self.db_data, &tx, mined)?;
            self.record_tx_transparent_receives(&tx, mined);
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
        // Build the owned outputs (each with its gap-lookahead index, if the matched address has
        // no `addresses` row yet) while holding the (immutable) matcher borrow, then record them
        // with `&mut self.db_data` - keeping the two borrows from overlapping.
        let (account, outputs): (AccountUuid, Vec<_>) = {
            let Some(matcher) = self.transparent_scripts.as_ref() else {
                return 0;
            };
            let Some(bundle) = tx.transparent_bundle() else {
                return 0;
            };
            let txid = tx.txid();
            let outputs = bundle
                .vout
                .iter()
                .enumerate()
                .filter_map(|(index, txout)| {
                    engine::owned_transparent_output(
                        &matcher.all,
                        txid,
                        index as u32,
                        u64::from(txout.value()),
                        txout.script_pubkey().0 .0.clone(),
                        h,
                    )
                    .map(|o| {
                        let lookahead = matcher.lookahead_index(o.recipient_address());
                        (o, lookahead)
                    })
                })
                .collect();
            (matcher.account, outputs)
        };
        let mut recorded = 0;
        for (output, lookahead) in outputs {
            // A gap-lookahead match must record its `addresses` row first (see
            // `engine::record_lookahead_address`), or the put below rejects the output.
            if let Some(index) = lookahead {
                if let Err(e) = engine::record_lookahead_address(&mut self.db_data, account, index)
                {
                    warn!("recording lookahead transparent address at index {index} failed: {e}");
                    continue;
                }
            }
            match self.db_data.put_received_transparent_utxo(&output) {
                Ok(_) => recorded += 1,
                Err(e) => warn!(
                    "recording transparent receive {}:{} failed: {e}",
                    output.outpoint().txid(),
                    output.outpoint().n(),
                ),
            }
        }
        if recorded > 0 {
            // A new receive may have extended the transparent gap; rebuild the set next pass.
            self.transparent_set_dirty = true;
            // New unspent outputs to watch for spends.
            self.transparent_unspent_dirty = true;
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
                info!("transparent initial sync already complete ({depth} addresses)");
            }
            return false;
        }
        if self.transparent_preexpose.is_none() {
            self.transparent_preexpose = Some(PreexposeProgress {
                done: start,
                total: depth,
                throttle: crate::progress::ProgressThrottle::new(
                    PREEXPOSE_LOG_INTERVAL,
                    u64::from(start),
                ),
            });
            if start > 0 {
                info!("resuming transparent initial sync at {start}/{depth} addresses");
            } else {
                info!("starting transparent initial sync: {depth} addresses to scan");
            }
        }
        let end = depth.min(start.saturating_add(TRANSPARENT_PREEXPOSE_CHUNK));
        // Deriving a chunk of diversified addresses is CPU-bound (FF1 + key derivation per index)
        // and DB-bound (an upsert per index). Two things keep it from freezing the daemon for the
        // whole multi-minute window - #81 chunked the work but still ran each chunk *synchronously*
        // on the actor's runtime worker, so read RPCs still stalled (see the regression guard in
        // `regtest_transparent_preexpose_responsive.rs`):
        //   * `block_in_place` tells tokio to relocate the other tasks on this worker to a sibling
        //     thread for the duration of the burst - exactly as the block scan does - so read RPCs
        //     (which bypass the actor on their own short-lived SQLite connections) keep getting
        //     scheduled; and
        //   * `transactionally` batches the whole chunk into a single SQLite transaction, so we pay
        //     one commit per chunk instead of one per address - which both cuts the wall-clock and
        //     avoids the WAL churn that would otherwise slow fresh read connections.
        // The chunk boundary in `sync_step` then yields to the runtime so the actor task actually
        // suspends between chunks rather than tight-looping through them synchronously.
        let derived = tokio::task::block_in_place(|| {
            self.db_data
                .transactionally::<_, _, SqliteClientError>(|wdb| {
                    for i in start..end {
                        let div = DiversifierIndex::from(i);
                        wdb.get_address_for_index(account_id, div, request)?;
                    }
                    Ok(())
                })
        });
        if let Err(e) = derived {
            warn!("transparent initial sync failed in [{start}, {end}): {e}");
            // Stop attempting this process so we don't spin re-hitting the same chunk every pass;
            // the transaction rolled back, so the window stays exposed up to `start` and a later
            // restart resumes there via `next_unexposed_external_index`.
            return false;
        }
        if let Some(p) = self.transparent_preexpose.as_mut() {
            p.done = end;
        }
        if end >= depth {
            let elapsed = self
                .transparent_preexpose
                .as_ref()
                .map(|p| p.throttle.elapsed_secs())
                .unwrap_or(0.0);
            info!(
                addresses = depth,
                elapsed_secs = elapsed as u64,
                "transparent initial sync complete"
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
        let Some(p) = self.transparent_preexpose.as_mut() else {
            return;
        };
        let done = p.done;
        let total = p.total;
        let Some(w) = p.throttle.tick(u64::from(done)) else {
            return;
        };
        let (pct, rate, eta) = preexpose_progress_stats(done, total, w.did as u32, w.window_secs);
        info!(
            exposed = done,
            total,
            percent = (pct * 10.0).round() / 10.0,
            rate_per_sec = rate.round(),
            eta = %eta,
            "transparent initial sync in progress"
        );
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
                tracing::debug!("skipping unparseable mempool tx: {e}");
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
                let ours = t_recorded > 0 || super::read::tx_exists(&self.engine_dir, &txid_hex);
                tracing::debug!(
                    "processed mempool tx {txid} (ours={ours}, transparent_receives={t_recorded})"
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
            Err(e) => warn!("failed to store mempool tx {txid}: {e}"),
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
        match super::read::unmined_txids(&self.engine_dir) {
            Ok(unmined) => {
                let unmined: std::collections::HashSet<String> = unmined.into_iter().collect();
                map.retain(|txid, _| unmined.contains(txid));
            }
            Err(e) => tracing::debug!("pruning first-seen map: {e}"),
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
        // after creating the account (birthday now set -> the scan floors at the birthday). We
        // still record the tip height/hash below so the bootstrap can run.
        let (tip, hash) = if self.account_id.is_some() {
            fetch_and_store_chain_tip(client, &mut self.db_data).await?
        } else {
            fetch_chain_tip(client).await?
        };
        self.tip_height = Some(u32::from(tip));
        // A successful tip refresh is the first proof the connection actually works end to end,
        // so it - not the bare `connect()` - is where the reconnect backoff resets. This keeps
        // the backoff growing across a reachable-but-degraded upstream (connect succeeds, refresh
        // fails) instead of resetting to the base delay on every failed cycle.
        self.backoff.reset();
        // Announce a freshly established connection now that we know the upstream's tip. Logged
        // once per connection (reset by `mark_disconnected`), so connect/disconnect pair up.
        if !self.connected_logged {
            self.connected_logged = true;
            info!(
                server = %self.server.describe(),
                tip = u32::from(tip),
                "connected to the upstream"
            );
        }
        tracing::debug!(
            "tip refreshed: {:?} -> {} (suggest_scan_ranges drives the rescan/rewind)",
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
                    // Make the chunk boundary a real runtime yield, not just an actor-loop return:
                    // during pre-exposure neither the loop's `try_recv` nor `sync_step` hit a pending
                    // await, so without this the actor task would poll straight into the next chunk
                    // and never suspend - monopolizing its worker for the whole window. Yielding hands
                    // control back to the scheduler each chunk so other tasks (and queued commands on
                    // the next loop turn) get a window.
                    tokio::task::yield_now().await;
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
            if self.transparent_unspent_dirty {
                self.rebuild_transparent_unspent();
            }
        }

        let outcome = {
            let transparent = self.transparent_scripts.as_ref();
            let unspent = self.transparent_unspent.as_ref();
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| anyhow!("not connected"))?;
            engine::sync_one_batch(
                client,
                &self.network,
                &self.engine_dir,
                &mut self.db_cache,
                &mut self.db_data,
                transparent,
                unspent,
            )
            .await?
        };
        // A recorded receive may have extended the transparent gap (exposing new indices), so
        // rebuild the address set before the next pass to cover them.
        if outcome.transparent_recorded > 0 {
            self.transparent_set_dirty = true;
        }
        // A recorded receive adds an outpoint to watch; a recorded spend removes one. Either way
        // the membership set is stale, so rebuild it before the next pass.
        if outcome.transparent_recorded > 0 || outcome.transparent_spends_recorded > 0 {
            self.transparent_unspent_dirty = true;
        }
        self.update_status();
        Ok(outcome.worked)
    }

    /// Rebuild [`Self::transparent_scripts`] from the account's recorded transparent receivers
    /// (external + internal/change) plus the in-memory gap lookahead: the next
    /// `transparent_gap_limit` external indices past the issuance frontier
    /// (`max(transparent_initial_scan, highest exposed external index + 1)`), derived from the
    /// account's external incoming viewing key without touching the database (see
    /// [`engine::TransparentMatcher`]). The lookahead is what makes the gap limit compose with
    /// `transparent_initial_scan` - a receive within one gap of the frontier is discovered (and
    /// recorded, which slides the frontier) even though librustzcash's own gap window only
    /// extends past *funded* indices. Cheap relative to a sync batch and only run when the set
    /// may have changed (`transparent_set_dirty`), so an exchange with ~100k addresses pays the
    /// query once per gap extension, not once per scanned block.
    fn rebuild_transparent_set(&mut self, account_id: AccountUuid) {
        let receivers = match self
            .db_data
            .get_transparent_receivers(account_id, true, false)
        {
            Ok(r) => r,
            Err(e) => {
                warn!("rebuilding transparent address set: {e}");
                return;
            }
        };
        let mut all: HashSet<TransparentAddress> = receivers.into_keys().collect();
        // The frontier and the already-recorded external indices come from one external-only
        // metadata query: recorded indices are skipped below without deriving them, so the
        // lookahead's per-rebuild derivation cost is bounded by the indices librustzcash has
        // NOT already materialized (its funded-anchored window is generated in full at account
        // creation) - a legacy wide-gap config doesn't re-derive its whole window here on every
        // rebuild, only the sliver past it.
        use zcash_client_backend::wallet::Exposure;
        let external = match self
            .db_data
            .get_transparent_receivers(account_id, false, false)
        {
            Ok(r) => r,
            Err(e) => {
                warn!("rebuilding transparent address set: {e}");
                return;
            }
        };
        let mut recorded_external: HashSet<u32> = HashSet::new();
        let mut frontier = self.transparent_initial_scan;
        for meta in external.values() {
            if let Some(i) = meta.address_index() {
                let index = i.index();
                recorded_external.insert(index);
                if matches!(meta.exposure(), Exposure::Exposed { .. }) {
                    frontier = frontier.max(index.saturating_add(1));
                }
            }
        }
        let mut lookahead = HashMap::new();
        if let Some(ivk) = self.external_transparent_ivk(account_id) {
            use zcash_transparent::keys::{IncomingViewingKey as _, NonHardenedChildIndex};
            for index in frontier..frontier.saturating_add(self.transparent_gap_limit) {
                // Only addresses without a DB row belong in the lookahead map - a recorded
                // receiver (e.g. a librustzcash-generated funded-window gap row) is already in
                // `all` and needs no row created at match time, so skip the derivation too.
                if recorded_external.contains(&index) {
                    continue;
                }
                let Some(child) = NonHardenedChildIndex::from_index(index) else {
                    break;
                };
                // A non-derivable child index yields no address at all (matching upstream's
                // behavior of skipping it); the gap window just has one fewer member.
                if let Ok(addr) = ivk.derive_address(child) {
                    if all.insert(addr) {
                        lookahead.insert(addr, index);
                    }
                }
            }
        }
        // Two windows, deliberately different (see the transparent notes in the project docs):
        // `frontier` follows *exposure*, so live matching covers `frontier .. frontier +
        // gap_limit` and a wallet always credits receives on addresses it handed out. The
        // *recovery* horizon (`transparent_initial_scan + transparent_gap_limit`) follows
        // *funding*, and is what bounds a from-seed restore. Log both so the difference is
        // visible when a wallet has issued past its recovery horizon.
        tracing::debug!(
            "transparent address set rebuilt: {} receiver(s) ({} gap-lookahead from index \
             {frontier}, live coverage through {}; recovery horizon {})",
            all.len(),
            lookahead.len(),
            frontier.saturating_add(self.transparent_gap_limit),
            self.transparent_initial_scan
                .saturating_add(self.transparent_gap_limit),
        );
        self.transparent_frontier = Some(frontier);
        self.transparent_scripts = Some(engine::TransparentMatcher {
            account: account_id,
            all,
            lookahead,
        });
        self.transparent_set_dirty = false;
    }

    /// Refresh the unspent-transparent-outpoint set the block scan matches spends against. One
    /// indexed query bounded by the outputs the wallet actually holds - not by how many addresses
    /// it has issued - so it stays cheap for a wallet tracking a large address set.
    fn rebuild_transparent_unspent(&mut self) {
        match crate::wallet::read::unspent_transparent_outpoints(&self.engine_dir) {
            Ok(set) => {
                tracing::debug!(
                    "watching {} unspent transparent outpoint(s) for spends",
                    set.len()
                );
                self.transparent_unspent = Some(set);
                self.transparent_unspent_dirty = false;
            }
            // Leave the previous set in place: a stale set still catches most spends, and the
            // next pass retries. Never fatal - this is discovery, not consensus.
            Err(e) => warn!("rebuilding the unspent transparent outpoint set: {e}"),
        }
    }

    /// The account's external transparent incoming viewing key (for deriving the gap-lookahead
    /// addresses), or `None` when the account's UIVK carries no transparent component.
    fn external_transparent_ivk(
        &self,
        account_id: AccountUuid,
    ) -> Option<zcash_transparent::keys::ExternalIvk> {
        let account = self.db_data.get_account(account_id).ok()??;
        account.uivk().transparent().clone()
    }

    /// Rebuild the wallet account from `keys.toml` on an empty data directory (the bootstrap
    /// path). Best-effort and idempotent: requires the seed to be loaded (so an encrypted wallet
    /// waits for its first `walletpassphrase`), a live upstream, and a known tip; when any is
    /// missing it returns and is retried on the next pass. The birthday's tree state is fetched
    /// fresh from the upstream (never cached on disk), reusing the exact path `zecd init` takes.
    async fn maybe_bootstrap_account(&mut self) {
        let Some((birthday_height, bootstrap_key)) = self.pending_bootstrap.as_ref() else {
            return;
        };
        let birthday_height = *birthday_height;
        if self.account_id.is_some() {
            self.pending_bootstrap = None;
            return;
        }
        // A seed rebuild needs the seed (a copy, zeroized on drop); absent means the wallet is
        // still locked, and the bootstrap is retried on a later pass. A view-only rebuild needs
        // no secret at all - the pinned key is already in hand.
        let seed = match bootstrap_key {
            BootstrapKey::Seed => match seed_guard(&self.seed).clone_seed() {
                Some(seed) => Some(seed),
                None => return,
            },
            BootstrapKey::Ufvk(_) => None,
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
                    warn!("bootstrap: fetching birthday tree state failed: {e}");
                    self.client = None;
                    return;
                }
                Err(_) => {
                    warn!("bootstrap: birthday tree-state fetch timed out");
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
                "bootstrap: treestate height mismatch - requested {prior}, upstream \
                 returned {treestate_returned}"
            );
        }
        let birthday =
            match AccountBirthday::from_treestate(treestate, Some(BlockHeight::from_u32(tip))) {
                Ok(b) => b,
                Err(_) => {
                    warn!("bootstrap: could not derive account birthday from tree state");
                    return;
                }
            };
        // Same account label and same creation calls `zecd init` makes, so a rebuilt account is
        // indistinguishable from a freshly initialized one - which is what lets the binding
        // verification below hold it to the same pin.
        let created = match (&self.pending_bootstrap, &seed) {
            (Some((_, BootstrapKey::Seed)), Some(seed)) => self
                .db_data
                .create_account("primary", seed, &birthday, None)
                .map(|_| ()),
            (Some((_, BootstrapKey::Ufvk(ufvk))), _) => self
                .db_data
                .import_account_ufvk(
                    "primary",
                    ufvk,
                    &birthday,
                    zcash_client_backend::data_api::AccountPurpose::ViewOnly,
                    None,
                )
                .map(|_| ()),
            // `pending_bootstrap` was checked at entry and nothing clears it in between.
            _ => return,
        };
        if let Err(e) = created {
            warn!("bootstrap: creating the account failed: {e}");
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
                            "bootstrap: {e}. The rebuilt account is left unadopted; \
                             restarting the daemon will surface this as a startup failure."
                        );
                        self.pending_bootstrap = None;
                        return;
                    }
                }
                self.account_id = Some(id);
                self.account_index = index;
                self.watch_only = watch_only;
                self.pending_bootstrap = None;
                // The rebuilt account's default-address anchor for the recovery horizon (the
                // same derivation `spawn` runs for a wallet that starts with an account).
                if self.transparent_enabled {
                    self.transparent_default_frontier =
                        default_transparent_frontier(&self.db_data, id);
                }
                // First `update_chain_tip` with the account (and its birthday) now present - see
                // `refresh_tip`. This is what derives the scan queue with a non-NULL
                // `wallet_birthday`, so the rescan floors at the birthday instead of an
                // in-progress subtree boundary far below it.
                if let Err(e) = self.db_data.update_chain_tip(BlockHeight::from_u32(tip)) {
                    warn!("bootstrap: update_chain_tip after account creation failed: {e}");
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
                        tracing::debug!("bootstrap: suggest_scan_ranges for log failed: {e}");
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
                            "bootstrap: scan floor {} is {} blocks below birthday {} - far \
                             below the wallet birthday; the rescan will scan history it need not \
                             (check shard alignment / wallet_birthday)",
                            scan_floor.unwrap_or(0),
                            gap,
                            birthday
                        );
                    }
                }
                self.update_status();
            }
            Ok(None) => warn!("bootstrap: account missing immediately after creation"),
            Err(e) => warn!("bootstrap: re-reading the new account failed: {e}"),
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
        // `scanning` and `scan_progress` are height-based (`fully_scanned` vs the chain tip), NOT
        // librustzcash's note-weighted `progress().scan()` ratio - that ratio covers only the
        // tip-priority range and reads 1.0 while historical ranges are still scanning (see
        // [`scan_progress_ratio`]), which previously flipped `scanning` false mid-restore: the
        // status RPCs (`getwalletinfo.scanning`, `initialblockdownload`, `getpeerinfo.syncing`)
        // reported the scan done hours early, and `pending_enhancements` was measured (one DB
        // read per status update) throughout the scan it was designed to skip.
        let (fully_scanned, scan_progress, scanning) = match (summary, self.tip_height) {
            (Some(s), Some(tip)) => {
                let scanned = u32::from(s.fully_scanned_height());
                (
                    Some(scanned),
                    scan_progress_ratio(self.birthday, scanned, tip),
                    scanned < tip,
                )
            }
            // `summary` is only computed once a tip is known, so this is the "no summary yet"
            // arm either way: heights unknown, conservatively still scanning.
            _ => (None, 0.0, true),
        };

        // The enhancement backlog is the work that remains *after* the block scan reaches the tip
        // (memos, full transparent data - see `enhance_step`). While the block scan is still
        // running it dominates readiness via the height gap, so don't pay the extra DB read; once
        // caught up, this count is what stands between "scanned to tip" and "ready to serve full
        // history", so measure it fresh. `0` while scanning means "not yet measured", not "drained".
        //
        // `enhanced_through` rides the same measurement: the lowest height any pending request
        // still refers to, minus one, clamped to the scanned frontier (nothing above it has
        // been scanned, let alone enhanced). An empty backlog means the whole scanned range is
        // enhanced. While scanning it is `None` - unmeasured, and a consumer must not advance a
        // memo cursor on an unknown, so this deliberately reads as "don't know" rather than
        // falling back to `fully_scanned`.
        let (pending_enhancements, enhanced_through) = if scanning {
            (0, None)
        } else {
            let (count, lowest) = self.enhancement_backlog();
            (
                count,
                fully_scanned.map(|scanned| enhanced_through(scanned, lowest)),
            )
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
            enhanced_through,
            encrypted: self.encrypted,
            watch_only: self.watch_only,
            unlocked_until,
            transparent_frontier: self.transparent_frontier,
            transparent_recovery_horizon: self
                .transparent_enabled
                .then(|| self.transparent_recovery_horizon()),
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
        let txs = match read::unmined_raw_txs(&self.engine_dir, tip) {
            Ok(txs) => txs,
            Err(e) => {
                warn!("querying unmined txs for rebroadcast: {e}");
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
                        info!("re-broadcast unmined tx {txid}");
                    } else {
                        tracing::debug!(
                            "rebroadcast of {txid} rejected (code {}): {}",
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
                request,
                diversifier_index,
                reply,
            } => {
                let res = self.get_address_for_account(request, diversifier_index);
                let _ = reply.send(res);
            }
            WalletCommand::Send {
                request,
                confirmations,
                privacy,
                source,
                reply,
            } => {
                self.begin_or_queue_send(request, confirmations, privacy, source, reply)
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
            WalletCommand::SyncNow { reply } => {
                // Record the nudge and acknowledge immediately: the pass itself runs on the
                // next loop iteration, and the caller waits on `SyncStatus` for its result.
                // A halted wallet is the one case a nudge cannot help - say so rather than
                // acknowledging a pass that will never run.
                let res = if self.sync_halted {
                    Err(RpcError::misc(
                        "sync is halted for this wallet; run `zecd rescan` to rebuild it",
                    ))
                } else {
                    self.force_sync = true;
                    Ok(())
                };
                let _ = reply.send(res);
            }
            WalletCommand::Lock { reply } => {
                let res = self.do_lock();
                let _ = reply.send(res);
            }
            WalletCommand::SignMessage {
                address,
                message,
                reply,
            } => {
                let res = self.do_sign_message(address, &message);
                let _ = reply.send(res);
            }
            WalletCommand::ProposeShieldCoinbase {
                from,
                to_address,
                memo,
                limit,
                reply,
            } => {
                let res = self
                    .do_propose_shield_coinbase(from, to_address, memo, limit)
                    .await;
                let _ = reply.send(res);
            }
            WalletCommand::ExecuteShieldCoinbase { proposal, reply } => {
                let res = self.do_execute_shield_coinbase(*proposal).await;
                let _ = reply.send(res);
            }
            WalletCommand::ProposeMergeToAddress {
                source,
                to_address,
                memo,
                transparent_limit,
                shielded_limit,
                privacy,
                reply,
            } => {
                let res = self
                    .do_propose_merge_to_address(
                        source,
                        to_address,
                        memo,
                        transparent_limit,
                        shielded_limit,
                        privacy,
                    )
                    .await;
                let _ = reply.send(res);
            }
            WalletCommand::ExecuteMergeToAddress { work, reply } => {
                let res = self.do_execute_merge_to_address(*work).await;
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
            info!(target: "zecd::audit", "wallet auto-locked (walletpassphrase timeout elapsed)");
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
            ReceiverRequest::Transparent => return Ok(self.new_transparent_address()?.0),
            ReceiverRequest::Default if self.transparent_default => {
                return Ok(self.new_transparent_address()?.0)
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
    ///
    /// Returns the encoded address together with the BIP 44 external child index it was derived
    /// at. `getnewaddress` discards the index (Bitcoin Core's contract is a bare string), but
    /// `z_getaddressforaccount` reports it - the index is what an operator needs to reconcile an
    /// issued address against its derivation path.
    fn new_transparent_address(&mut self) -> Result<(String, u32), RpcError> {
        if !self.transparent_enabled {
            return Err(transparent_not_enabled());
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
            Ok(Some((ua, j))) => {
                let taddr = transparent_receiver(&ua)?;
                self.warn_if_gap_low(account_id, &taddr);
                use zcash_keys::encoding::AddressCodec as _;
                // The request requires a p2pkh receiver, so librustzcash can only have honoured
                // it at an index inside the BIP 44 non-hardened range - the conversion cannot
                // fail for an address it just derived.
                let index = transparent_child_index(j).ok_or_else(|| {
                    RpcError::wallet(format!(
                        "derived transparent address at diversifier index {} outside the BIP 44 \
                         non-hardened child range",
                        u128::from(j)
                    ))
                })?;
                Ok((taddr.encode(&self.network), index))
            }
            Ok(None) => Err(RpcError::wallet(
                "no transparent address available for account; the account's viewing key may \
                 not support a transparent receiver"
                    .to_string(),
            )),
            // librustzcash fails closed once its funded-anchored gap window (`gap_limit`
            // consecutive unfunded addresses) is full. That window is not the whole recovery
            // story - the `initial_scan + gap_limit` horizon covers the floor-anchored half - so
            // classification (recoverable / warn / fail closed) happens in the beyond-gap path.
            Err(SqliteClientError::ReachedGapLimit(..)) => {
                self.new_transparent_address_beyond_gap(account_id)
            }
            Err(e) => Err(RpcError::wallet(format!("address generation failed: {e}"))),
        }
    }

    /// Issue a transparent receiving address past librustzcash's funded-anchored gap window
    /// (`get_next_available_address` hit `ReachedGapLimit`), classifying the next sequential
    /// external index against the stateless-restore **recovery horizon** (`gap_limit` past the
    /// restore floor - see [`recovery_horizon_for`]):
    ///
    ///   * `next < horizon` - recoverable from seed (a restore pre-exposes `0..initial_scan` and
    ///     its gap lookahead matches `gap_limit` indices past that frontier), so the address is
    ///     issued quietly regardless of `transparent_allow_beyond_recovery_window`, with a
    ///     near-exhaustion warning as the horizon fills;
    ///   * `next >= horizon` - only funding can make the index reachable on a restore, so with
    ///     the operator's opt-in it is issued with a loud warning, and otherwise the call fails
    ///     closed with an actionable error.
    ///
    /// Either way the index is exposed directly via `get_address_for_index` (the same primitive
    /// the A18 initial sync uses), since librustzcash's gap reservation refuses it.
    fn new_transparent_address_beyond_gap(
        &mut self,
        account_id: AccountUuid,
    ) -> Result<(String, u32), RpcError> {
        let next = self.next_external_transparent_index(account_id);
        Ok((self.expose_transparent_index(account_id, next)?, next))
    }

    /// Derive, persist, and expose the external transparent receiver at `index`, applying the
    /// stateless-restore recovery-horizon policy described on
    /// [`Self::new_transparent_address_beyond_gap`]. Shared by that sequential beyond-gap path
    /// and by `z_getaddressforaccount`'s explicit-index derivation, so an operator asking for a
    /// specific index gets exactly the same recoverability guarantees (and refusals) as one
    /// taking the next address from `getnewaddress`.
    fn expose_transparent_index(
        &mut self,
        account_id: AccountUuid,
        index: u32,
    ) -> Result<String, RpcError> {
        let horizon = self.transparent_recovery_horizon();
        if index >= horizon && !self.transparent_allow_beyond_recovery_window {
            return Err(RpcError::wallet(format!(
                "transparent address gap limit reached: external index ({index}) is \
                 beyond the recovery horizon ({horizon} = transparent_gap_limit past the \
                 restore floor), so it would not be recoverable from seed. Raise [pools] \
                 transparent_initial_scan to your issuance high-water mark (preferred - a \
                 large transparent_gap_limit makes every recorded transparent receive \
                 re-derive the whole window), fund a lower-index address, or set \
                 transparent_allow_beyond_recovery_window = true to issue beyond the horizon \
                 anyway."
            )));
        }
        // Exposing an index outside the current gap window widens what the block-scan / mempool
        // matcher must recognize; mark its address set stale so the next sync pass rebuilds it.
        self.transparent_set_dirty = true;
        let request = crate::pools::transparent_extraction_request();
        let div = DiversifierIndex::from(index);
        let ua = self
            .db_data
            .get_address_for_index(account_id, div, request)
            .map_err(map_address_for_index_error)?
            .ok_or_else(|| {
                RpcError::wallet(format!("Error: no address at diversifier index {index}."))
            })?;
        let taddr = transparent_receiver(&ua)?;
        if index < horizon {
            info!(
                "issued transparent address at external index {index}, past the \
                 funded-anchored gap window but within the recovery horizon ({horizon}) - \
                 recoverable from seed."
            );
            let remaining = horizon_slots_remaining(horizon, index);
            if remaining <= self.transparent_gap_warn_threshold {
                warn!(
                    "transparent recovery horizon nearly exhausted: {remaining} recoverable \
                     address slot(s) remain (recovery horizon = {horizon}). Raise [pools] \
                     transparent_initial_scan to your issuance high-water mark before handing \
                     out more addresses."
                );
            }
        } else {
            warn!(
                target: "zecd::audit",
                "issued transparent address at external index {index}, OUTSIDE the \
                 stateless-restore recovery horizon ({horizon}). Funds received here may be \
                 UNRECOVERABLE from seed unless you raise [pools] transparent_initial_scan \
                 past this index (preferred - a large transparent_gap_limit makes every \
                 recorded transparent receive re-derive the whole window). (permitted by \
                 transparent_allow_beyond_recovery_window = true)"
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

    /// This wallet's stateless-restore recovery horizon: `gap_limit` past the restore floor
    /// (`max(transparent_initial_scan, default-address frontier)`) - see [`recovery_horizon_for`].
    fn transparent_recovery_horizon(&self) -> u32 {
        recovery_horizon_for(
            self.transparent_initial_scan,
            self.transparent_default_frontier,
            self.transparent_gap_limit,
        )
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
    /// `transparent_gap_warn_threshold` recoverable slots before `getnewaddress` would leave the
    /// recovery coverage, so the operator can widen it before addresses start landing outside.
    /// Coverage is the larger of the two restore mechanisms at this index: librustzcash's
    /// funded-anchored gap window (`GapMetadata::InGap`) and the floor-anchored recovery horizon
    /// (`transparent_initial_scan + transparent_gap_limit`) - a wallet whose pre-exposed floor
    /// fills the funded window (0 in-window slots) is still fine while the horizon has room.
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
            // Count the recovery horizon as headroom alongside the gap window, so an intended
            // small-gap + large-initial-scan wallet isn't warned on every issuance it can in
            // fact recover (see [`horizon_slots_remaining`]).
            let horizon = self.transparent_recovery_horizon();
            let in_window = gap_slots_remaining(gap_position, gap_limit);
            let under_horizon = meta
                .address_index()
                .map_or(0, |i| horizon_slots_remaining(horizon, i.index()));
            let remaining = in_window.max(under_horizon);
            if remaining <= self.transparent_gap_warn_threshold {
                warn!(
                    "transparent recovery window nearly exhausted: {remaining} recoverable \
                     address slot(s) remain (gap_limit={gap_limit}, recovery horizon={horizon}) \
                     before getnewaddress can no longer issue an address recoverable from seed. \
                     Raise [pools] transparent_initial_scan past your issuance high-water mark \
                     (preferred - a large transparent_gap_limit makes every recorded transparent \
                     receive re-derive the whole window), or fund a lower-index address."
                );
            }
        }
    }

    /// Derive an address for this wallet's account, backing `z_getaddressforaccount`.
    /// With `diversifier_index = Some(j)` it derives at exactly that index (re-deriving an
    /// already-exposed index returns the same address; requesting a different receiver set at an
    /// exposed index is a reuse error); with `None` it picks the next unused index, exactly like
    /// `get_new_address`. A shielded `request` has already been validated against the enabled
    /// pools, and a transparent one against the wallet's transparent capability - both are
    /// re-checked here, since the actor is the authority on the wallet's configuration.
    /// Returns the encoded address, the index used, and the receivers derived.
    fn get_address_for_account(
        &mut self,
        request: ReceiverRequest,
        diversifier_index: Option<DiversifierIndex>,
    ) -> Result<DerivedAddress, RpcError> {
        let receivers = match request {
            ReceiverRequest::Transparent => {
                return self.transparent_address_for_account(diversifier_index)
            }
            ReceiverRequest::Default if self.transparent_default => {
                return self.transparent_address_for_account(diversifier_index)
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
        Ok(DerivedAddress {
            address: ua.encode(&self.network),
            index: u128::from(j),
            receiver_types: receivers.iter().map(|p| p.as_str()).collect(),
        })
    }

    /// The transparent half of [`Self::get_address_for_account`]: derive a **bare** transparent
    /// receiver, either at an explicit BIP 44 external child index or (index omitted) the next
    /// one `getnewaddress` would hand out.
    ///
    /// ZIP-316 forbids a transparent-only Unified Address, so - exactly as `getnewaddress "" \
    /// "transparent"` does - the derived UA's transparent receiver is extracted and encoded bare;
    /// zecd never mixes a transparent receiver into a UA it hands out. Deriving at an explicit
    /// index goes through [`Self::expose_transparent_index`], so the recovery-horizon policy
    /// (`transparent_allow_beyond_recovery_window` and its warnings) applies identically, and the
    /// address is *exposed*: the block-scan / mempool matcher will credit a payment to it.
    ///
    /// Re-deriving an index this wallet already exposed as a *shielded* address is librustzcash's
    /// `DiversifierIndexReuse` error (mapped to zcashd's wording): one index carries one receiver
    /// set. Transparent indices are dense from 0, while shielded ones are clock-derived, so the
    /// two ranges do not collide in practice.
    fn transparent_address_for_account(
        &mut self,
        diversifier_index: Option<DiversifierIndex>,
    ) -> Result<DerivedAddress, RpcError> {
        if !self.transparent_enabled {
            return Err(transparent_not_enabled());
        }
        let (address, index) = match diversifier_index {
            None => self.new_transparent_address()?,
            Some(j) => {
                let index = transparent_child_index(j).ok_or_else(|| {
                    RpcError::invalid_parameter(format!(
                        "diversifier index {} is not a valid transparent child index: a \
                         transparent receiver is derived at a BIP 44 non-hardened index, so it \
                         must be less than {}.",
                        u128::from(j),
                        1u32 << 31
                    ))
                })?;
                let account_id = self.require_account()?;
                (self.expose_transparent_index(account_id, index)?, index)
            }
        };
        Ok(DerivedAddress {
            address,
            index: u128::from(index),
            // zcashd's token for a transparent receiver (there is no "p2sh" derivation).
            receiver_types: vec!["p2pkh"],
        })
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
                    "could not reach upstream to sync before sending ({e}); building \
                     against the last-scanned height"
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

    /// Whether sends on this wallet *may* use the cached-Orchard PCZT path (so prove and store are
    /// separable). True for the default Orchard-only wallet with `cache_proving_key` on. A
    /// Sapling-spending wallet (or `cache_proving_key` off) uses the fused path, which has no
    /// prove/store seam - see [`Self::do_send_fused`]. Ironwood (post-NU6.3) sends now ride this
    /// path too: `create_pczt_from_proposal` builds the Ironwood bundle, `prove_sign_pczt` proves it
    /// from the cached `PostNu6_3` key, and the extract step verifies it (see [`store_pczt`]).
    ///
    /// NB this gates on the *wallet's* pools, not the send's recipients: even when this is true, an
    /// individual send that pays a Sapling output is still diverted to the fused path
    /// (`request_pays_sapling_output`), because the cached path's extractor is handed no Sapling
    /// verifying key.
    fn cached_pczt_path(&self) -> bool {
        self.orchard_keys.is_some() && !self.enabled_pools.contains(Receiver::Sapling)
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
        let engine_dir = self.engine_dir.clone();
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
                // Shielded-only input selection, always: `SpendPolicy`'s default permits every
                // shielded pool with no transparent spending. A transparent-funded send
                // (`SendSource::Transparent`) never reaches this path - `do_send` routes it to
                // the fused path, whose `create_proposed_transactions` signs transparent inputs;
                // the PCZT prove+sign step has no transparent signing pass, so keeping the
                // default here makes an unsigned-transparent PCZT unconstructible by design.
                &SpendPolicy::default(),
                // No input locking: zecd serializes sends through the single-writer actor, so
                // there is no concurrent proposer to race for inputs.
                None,
                // `None` builds at the transaction version implied by the target height.
                None,
            )
            .map_err(|e| enrich_insufficient_funds(db, &engine_dir, policy, classify_err(e)))?;
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
                // `None` lets librustzcash derive the expiry from the proposal's target height,
                // matching the fused build path (and the pre-#2412 behaviour).
                None,
                // Selects the padding of the Orchard bundle only; the Ironwood bundle's is
                // derived from the proposal. The Orchard bundle is always padded to the default
                // action floor, which is what the change strategy above costed against.
                BundlePadding::DEFAULT,
            )
            .map_err(|e| {
                enrich_insufficient_funds(db, &engine_dir, policy, classify_pczt_err(e))
            })?;
            Ok((pczt, shape, start.elapsed()))
        })
    }

    /// Sign `message` with the private key of a transparent `address` the wallet owns
    /// (`signmessage`). The address must already be recorded for the account (its `(scope, index)`
    /// is read from the wallet DB); the key is derived from the seed exactly as a transparent send
    /// derives its input keys. Errors: `-13` if the wallet is locked, `-4` if it is watch-only or
    /// the address is not one of the wallet's own transparent receivers.
    fn do_sign_message(
        &mut self,
        address: TransparentAddress,
        message: &str,
    ) -> Result<String, RpcError> {
        // Match the send path: if an encrypted wallet's unlock elapsed but proactive relock hasn't
        // fired yet, lock now so a signature can't slip through past the timeout.
        self.relock_if_expired();
        let account_id = self.require_account()?;
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;

        // The address must be a recorded transparent receiver of this account. librustzcash only
        // knows the `(scope, index)` for addresses it has exposed/recorded - the same bound the
        // fully-transparent spend path relies on - so an address the wallet never handed out is
        // reported as unknown (Bitcoin Core's `-4`).
        let meta = self
            .db_data
            .get_transparent_address_metadata(account_id, &address)
            .map_err(RpcError::database_internal)?
            .ok_or_else(|| RpcError::wallet("Unknown address"))?;
        let (scope, index) = match meta.source() {
            TransparentAddressSource::Derived {
                scope,
                address_index,
            } => (*scope, *address_index),
            // Standalone imported keys/scripts only exist with the `transparent-key-import`
            // feature, which zecd does not enable.
            #[allow(unreachable_patterns)]
            _ => return Err(RpcError::wallet("Private key not available")),
        };

        let usk = seed_guard(&self.seed).derive_usk(self.network, account_index)?;
        let secret_key = usk
            .transparent()
            .derive_secret_key(scope, index)
            .map_err(|e| RpcError::wallet(format!("transparent key derivation failed: {e}")))?;

        Ok(crate::rpc::signmessage::sign_message_with_key(
            &secret_key,
            message,
        ))
    }

    /// Build, prove, and broadcast a send inline (today's behaviour): the whole of phase A->C runs
    /// on the actor under `block_in_place`, so the actor (and thus sync) is blocked for the whole
    /// proof. `[spend] pipeline_proving` moves the proof off the actor - see
    /// [`Self::begin_or_queue_send`]. Used directly when pipelining is disabled or ineligible.
    async fn do_send(
        &mut self,
        request: TransactionRequest,
        confirmations: Option<ConfirmationsPolicy>,
        privacy: SendPrivacy,
        source: SendSource,
    ) -> Result<TxId, RpcError> {
        // Hard backstop: if an encrypted wallet's unlock has expired but proactive relock
        // hasn't fired yet (e.g. a long sync batch was in progress), lock now so the spend
        // can't slip through past its timeout. `derive_usk` then returns -13 as expected.
        self.relock_if_expired();

        // Authoritative privacy gates for a transparent funding source (`z_sendmany` from a
        // t-address / `ANY_TADDR`). The RPC layer rejects both cases synchronously with the same
        // errors; re-checking here keeps the actor sound against any future caller. Spending
        // transparent UTXOs reveals the sender's addresses and input amounts, so it needs the
        // `AllowRevealedSenders` rung; paying a transparent recipient *from* transparent inputs
        // is a fully transparent transaction, which needs `AllowFullyTransparent` (zcashd's
        // split of the two).
        if matches!(source, SendSource::Transparent(_)) {
            if !privacy.allows_transparent_inputs() {
                return Err(insufficient_privacy_for_transparent_sender(privacy));
            }
            if privacy != SendPrivacy::AllowFullyTransparent
                && request_pays_transparent_output(&self.network, &request)
            {
                return Err(insufficient_privacy_for_fully_transparent());
            }
        }

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
        // pool. librustzcash's high-level proposal API can't express this (its change accounting
        // has no persistent transparent-change variant), so zecd builds and signs the transaction
        // itself. An explicitly *shielded* source (`z_sendmany` from a UA / shielded address)
        // must mean what it says, so it never takes this branch: its transparent recipients are
        // paid from shielded notes with shielded change, like any other policy's. Any other
        // policy, or any shielded recipient, falls through to the proposal path below.
        if privacy == SendPrivacy::AllowFullyTransparent && source != SendSource::Shielded {
            if let Some(recipients) = transparent_only_recipients(&self.network, &request)? {
                // A t-address `fromaddress` narrows the t->t selection to that address's UTXOs
                // (coin control); `ANY_TADDR` and the source-less Bitcoin-dialect sends spend
                // across every receiver, the pre-`SendSource` behaviour.
                let from = match source {
                    SendSource::Transparent(from) => from,
                    _ => None,
                };
                return self
                    .do_send_transparent(recipients, confirmations, usk, account_id, from)
                    .await;
            }
        }
        // A per-call `minconf` (z_sendmany) overrides the wallet-wide policy for this send's
        // note selection; the synchronous sends pass `None` and use the configured policy.
        let policy = confirmations.unwrap_or(self.confirmations_policy);

        // The cached-Orchard PCZT path can't finalize a Sapling output: its extractor is handed no
        // Sapling verifying key. A send to a Sapling-only recipient therefore takes the fused path,
        // which proves and verifies Sapling outputs itself. A transparent-funded send takes it
        // too: the PCZT prove+sign step has no transparent signing pass, while the fused
        // `create_proposed_transactions` derives the transparent input keys from the USK itself
        // (the same way `z_shieldcoinbase` executes its coinbase-shielding proposals).
        if !self.cached_pczt_path()
            || request_pays_sapling_output(&self.network, &request)
            || matches!(source, SendSource::Transparent(_))
        {
            return self
                .do_send_fused(
                    usk,
                    request,
                    policy,
                    privacy,
                    &spend_policy_for_source(source),
                )
                .await;
        }

        // Cached-Orchard PCZT path: phase A (select+build) -> phase B (prove+sign) -> phase C
        // (store), all on the actor. Each phase is timed so the send-latency log shows where the
        // cost lands on a large, note-fragmented wallet.
        let (pczt, shape, build) = self.build_proposal_and_pczt(request, policy, privacy)?;
        // Awaits the background keygen if this is the first send of a young daemon; a no-op once
        // it has finished. Only sends wait - reads and sync never touch the key.
        let keys = self
            .orchard_keys
            .clone()
            .expect("cached path")
            .get()
            .await?;
        let prover = self.prover.clone();
        let db = &mut self.db_data;
        let (txid, raw, prove, store): (TxId, Vec<u8>, Duration, Duration) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let p0 = Instant::now();
                let signed = prove_sign_pczt(pczt, &usk, &prover, &keys)?;
                let prove = p0.elapsed();
                let s0 = Instant::now();
                let txid = store_pczt(db, signed)?;
                let raw = read_raw_tx(db, txid)?;
                Ok((txid, raw, prove, s0.elapsed()))
            })?;

        let b0 = Instant::now();
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        log_send_latency("inline", shape, build, prove, store, b0.elapsed());
        Ok(txid)
    }

    /// The legacy fused send path: librustzcash's `create_proposed_transactions` builds, proves,
    /// and stores under one `&mut` (rebuilding the proving key per send). Used by a Sapling-
    /// spending wallet (the PCZT path here signs only Orchard spends), by a transparent-funded
    /// send (`create_proposed_transactions` signs transparent inputs from the USK; the PCZT
    /// prove+sign step cannot), or when `cache_proving_key` is off. Not pipelined - there is no
    /// prove/store seam to split. `spend_policy` is the input-side selection policy for this
    /// send's source (see [`spend_policy_for_source`]).
    async fn do_send_fused(
        &mut self,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        request: TransactionRequest,
        policy: ConfirmationsPolicy,
        privacy: SendPrivacy,
        spend_policy: &SpendPolicy,
    ) -> Result<TxId, RpcError> {
        let net = self.network;
        let change_pool = self.enabled_pools.change_pool();
        let orchard_action_limit = self.orchard_action_limit;
        let account_id = self.require_account()?;
        let prover: &LocalTxProver = &self.prover;
        let engine_dir = self.engine_dir.clone();
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
                    // The caller-selected input policy: `SpendPolicy::default()` (every shielded
                    // pool, no transparent spending - the historical fully-shielded selection)
                    // for a shielded source, or a transparent-only policy for a transparent
                    // `fromaddress` source (see `spend_policy_for_source`).
                    spend_policy,
                    // No input locking: zecd serializes sends through the single-writer actor,
                    // so there is no concurrent proposer to race for inputs.
                    None,
                    // `None` builds at the transaction version implied by the target height.
                    None,
                )
                .map_err(|e| enrich_insufficient_funds(db, &engine_dir, policy, classify_err(e)))?;
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
                    // `None` keeps the builder-derived expiry from the proposal's target
                    // height, matching the PCZT path.
                    None,
                )
                .map_err(|e| enrich_insufficient_funds(db, &engine_dir, policy, classify_err(e)))?;
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
        log_send_latency("fused", shape, build, prove, Duration::ZERO, b0.elapsed());
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
        source: SendSource,
        reply: oneshot::Sender<Result<TxId, RpcError>>,
    ) {
        // `AllowFullyTransparent` sends are handled inline by `do_send` (they build via the
        // transparent Builder, not the cached-Orchard PCZT prove path that pipelining accelerates),
        // so never queue them for off-actor proving.
        //
        // A transparent *source* (`z_sendmany` from a t-address / `ANY_TADDR`) can't ride the
        // pipeline either: the PCZT prove+sign step has no transparent signing pass, so `do_send`
        // diverts transparent-funded proposals to the fused path, which signs transparent inputs
        // itself. Routing here (before the queue) also keeps every queued send shielded-source.
        //
        // A Sapling-output send can't ride the pipeline either (it commits via the same PCZT
        // extractor that has no Sapling verifying key). Route it through `do_send`, which diverts
        // it to the fused path.
        if privacy == SendPrivacy::AllowFullyTransparent
            || matches!(source, SendSource::Transparent(_))
            || !self.pipeline_eligible()
            || request_pays_sapling_output(&self.network, &request)
        {
            let res = self.do_send(request, confirmations, privacy, source).await;
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
        // As on the inline path, this awaits the background keygen only on a young daemon's
        // first send. It happens before `send_in_flight` is set, so a keygen failure leaves the
        // pipeline free rather than wedged.
        let keys = match self
            .orchard_keys
            .clone()
            .expect("pipeline requires cached keys")
            .get()
            .await
        {
            Ok(k) => k,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let done_tx = self.send_done_tx.clone();
        // The prove runs off the actor task, so the wallet span does not follow it; carry it
        // into the closure so the panic/failure logs keep their wallet attribution.
        let span = tracing::Span::current();
        self.send_in_flight = true;
        tokio::task::spawn_blocking(move || {
            let _entered = span.enter();
            let p0 = Instant::now();
            // Isolate a proving panic: a completion MUST always be sent, or the pipeline would
            // wedge with `send_in_flight` stuck true.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                prove_sign_pczt(pczt, &usk, &prover, &keys)
            }))
            .unwrap_or_else(|_| {
                error!("send proof panicked off-actor; the actor continues");
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
        let db = &mut self.db_data;
        let _ = policy; // store rarely surfaces -6; kept for symmetry with the inline path.
        let (txid, raw, store): (TxId, Vec<u8>, Duration) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                let s0 = Instant::now();
                let txid = store_pczt(db, signed)?;
                let raw = read_raw_tx(db, txid)?;
                Ok((txid, raw, s0.elapsed()))
            })?;
        let b0 = Instant::now();
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        log_send_latency("pipelined", shape, build, prove, store, b0.elapsed());
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
                "pipelined send commit panicked; the actor continues (this is a bug - \
                 please report it)"
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
    ///
    /// `from` narrows the selection to one wallet-owned t-address's UTXOs (`z_sendmany` with a
    /// t-address `fromaddress` - coin control); `None` spends across every exposed receiver
    /// (`ANY_TADDR` and the source-less `sendtoaddress`/`sendmany`).
    async fn do_send_transparent(
        &mut self,
        recipients: Vec<(TransparentAddress, Zatoshis)>,
        confirmations: Option<ConfirmationsPolicy>,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        account_id: AccountUuid,
        from: Option<TransparentAddress>,
    ) -> Result<TxId, RpcError> {
        let net = self.network;
        let policy = confirmations.unwrap_or(self.confirmations_policy);
        // `self.prover` is an `Arc<LocalTxProver>` (shared for the pipeline); the transaction
        // builder wants `&LocalTxProver`, so deref-coerce through the Arc.
        let prover: &LocalTxProver = &self.prover;
        let engine_dir = self.engine_dir.clone();
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
                // internal/change), filtered for confirmations by the policy. Coinbase UTXOs are
                // excluded outright (`NonCoinbaseOnly`): consensus on mainnet/testnet requires a
                // transaction spending a transparent coinbase output to have an empty `vout`
                // (`bad-txns-coinbase-spend-has-transparent-outputs`), and this path always
                // produces transparent outputs - recipient(s) plus kept-transparent change. The
                // only legal route for coinbase funds is `z_shieldcoinbase` (coinbase →
                // shielded, no change), after which they spend as ordinary shielded notes.
                let receivers = db
                    .get_transparent_receivers(account_id, true, true)
                    .map_err(RpcError::database_internal)?;
                let mut utxos = Vec::new();
                for addr in receivers.keys() {
                    // Coin control: a t-address `fromaddress` restricts selection to that
                    // address's UTXOs. (The RPC layer has already verified it is wallet-owned.)
                    if from.is_some_and(|f| f != *addr) {
                        continue;
                    }
                    let outs = db
                        .get_spendable_transparent_outputs(
                            addr,
                            target_height,
                            policy,
                            CoinbaseFilter::NonCoinbaseOnly,
                            // zecd never locks inputs, so lock state can't exclude anything.
                            LockFilter::Unfiltered,
                        )
                        .map_err(RpcError::database_internal)?;
                    utxos.extend(outs);
                }
                if utxos.is_empty() {
                    // Distinguish "no transparent funds at all" from "only coinbase": the wallet
                    // may hold mature coinbase UTXOs that `listunspent`/`getbalance` display as
                    // spendable, so a bare "0 spendable" here would contradict what the caller
                    // just read. Same query as `getbalances.mine.coinbase`.
                    let coinbase =
                        super::read::mature_coinbase_zats(&engine_dir, u32::from(target_height))
                            .unwrap_or(0);
                    return Err(RpcError::insufficient_funds(if coinbase > 0 {
                        format!(
                            "Insufficient funds: 0 spendable non-coinbase transparent UTXOs; {}",
                            coinbase_hint(coinbase)
                        )
                    } else {
                        "Insufficient funds: 0 spendable transparent UTXOs".to_string()
                    })
                    .with_details(ErrorDetails::InsufficientFunds(InsufficientFunds {
                        available: Some(0),
                        mature_coinbase: coinbase,
                        ..Default::default()
                    })));
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
                        // As above: excluded mature coinbase may be exactly what the caller
                        // expected to cover the shortfall, so name it.
                        let coinbase = super::read::mature_coinbase_zats(
                            &engine_dir,
                            u32::from(target_height),
                        )
                        .unwrap_or(0);
                        let mut msg = "Insufficient funds: transparent UTXOs do not cover the \
                                       amount plus fee"
                            .to_string();
                        if coinbase > 0 {
                            msg = format!("{msg}; {}", coinbase_hint(coinbase));
                        }
                        // `required` stays unset: the selection that would have priced the fee
                        // is the one that just failed, so only the recipient total is known and
                        // reporting it as "required" would understate the real figure.
                        RpcError::insufficient_funds(msg).with_details(
                            ErrorDetails::InsufficientFunds(InsufficientFunds {
                                available: Some(values.iter().sum()),
                                mature_coinbase: coinbase,
                                ..Default::default()
                            }),
                        )
                    })?;
                utxos.truncate(n_selected);
                let selected = utxos;
                let fee_amount = Zatoshis::from_u64(fee_amount)
                    .map_err(|e| RpcError::misc(format!("fee value: {e}")))?;

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
                    Some((change_addr, change_val))
                } else {
                    None
                };

                // The shared build+sign+store core (also the t→t arm of `z_mergetoaddress`).
                build_signed_transparent_tx(
                    db,
                    net,
                    target_height,
                    &usk,
                    account_id,
                    &selected,
                    &recipients,
                    change_recipient,
                    fee_amount,
                    prover,
                )
            })?;

        // The send consumed some of the wallet's transparent outputs and created transparent
        // change: both sides of the watch set moved, so rebuild it before the next scan rather
        // than re-matching spends the wallet already recorded itself.
        self.transparent_unspent_dirty = true;
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        Ok(txid)
    }

    /// Build a `z_shieldcoinbase` proposal: mature (100+ conf) **coinbase** transparent UTXOs
    /// from the requested source addresses, swept into one shielded payment of
    /// `input_total - fee` with **no change in any pool** (a shielded change output would leak
    /// the sender's total selected-coinbase value, since the transparent input values are
    /// public). The coinbase-only restriction and the shielded-recipient requirement are both
    /// enforced by `propose_shielding_coinbase` at the API boundary; the 100-block maturity
    /// comes from `zcash_client_sqlite`'s selection SQL (keyed on `tx_index = 0`, which the
    /// sync engine records for block-scanned coinbase receives).
    ///
    /// This is the fast synchronous half (SQL + fee math - no proving); the returned proposal
    /// is executed later under the RPC's opid via `do_execute_shield_coinbase`. Between the two
    /// another send could in principle spend a selected UTXO; execution then fails cleanly on
    /// the operation (the same race zcashd's select-then-async-execute flow has).
    async fn do_propose_shield_coinbase(
        &mut self,
        from: crate::wallet::ShieldCoinbaseFrom,
        to_address: zcash_address::ZcashAddress,
        memo: Option<zcash_protocol::memo::MemoBytes>,
        limit: Option<usize>,
    ) -> Result<crate::wallet::ShieldCoinbasePlan, RpcError> {
        use zcash_client_backend::data_api::wallet::propose_shielding_coinbase;

        // Fail a locked or watch-only wallet synchronously (zcashd errors before returning an
        // opid); the derived key is dropped - execution re-derives its own.
        self.relock_if_expired();
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        let _ = seed_guard(&self.seed).derive_usk(self.network, account_index)?;

        // Same tip catch-up as a send: the proposal's target height (and thus the eventual tx's
        // expiry) must come from the real chain tip, not a lagging scanned height.
        self.sync_to_tip_for_send().await;

        let account_id = self.require_account()?;
        let net = self.network;
        let db = &mut self.db_data;

        let receivers = db
            .get_transparent_receivers(account_id, true, true)
            .map_err(RpcError::database_internal)?;
        let from_addrs: Vec<TransparentAddress> = match from {
            crate::wallet::ShieldCoinbaseFrom::AnyTaddr => receivers.keys().copied().collect(),
            crate::wallet::ShieldCoinbaseFrom::Address(t) => {
                if !receivers.contains_key(&t) {
                    return Err(RpcError::invalid_address_or_key(
                        "Invalid from address, no payment source found for address.",
                    ));
                }
                vec![t]
            }
        };

        let (target_height, _anchor) = db
            .get_target_and_anchor_heights(std::num::NonZeroU32::MIN)
            .map_err(RpcError::database_internal)?
            .ok_or_else(|| {
                RpcError::wallet("wallet has no chain tip yet; cannot build a transaction")
            })?;

        // Pre-flight: every *mature* coinbase UTXO the sources hold (the maturity clause rides
        // in the SQL). `remainingUTXOs`/`remainingValue` are computed by subtracting the
        // proposal's selection from this set, mirroring zallet/zcashd.
        let mut eligible_count = 0u64;
        let mut eligible_value = 0u64;
        for addr in &from_addrs {
            let outs = db
                .get_spendable_transparent_outputs(
                    addr,
                    target_height,
                    // Maturity (100 blocks) dominates any confirmations floor, so MIN is safe
                    // here - matching `propose_shielding_coinbase`'s own internal choice.
                    ConfirmationsPolicy::MIN,
                    CoinbaseFilter::CoinbaseOnly,
                    // zecd never locks inputs, so lock state can't exclude anything.
                    LockFilter::Unfiltered,
                )
                .map_err(RpcError::database_internal)?;
            for utxo in outs {
                eligible_count += 1;
                eligible_value += u64::from(utxo.txout().value());
            }
        }
        if eligible_count == 0 {
            return Err(RpcError::insufficient_funds(
                "Could not find any coinbase funds to shield.",
            ));
        }

        let proposal = propose_shielding_coinbase::<_, _, _, _, Infallible>(
            db,
            &net,
            &GreedyInputSelector::new(),
            &StandardFeeRule::Zip317,
            Zatoshis::ZERO,
            &from_addrs,
            to_address,
            memo,
            limit,
            // zecd does not lock inputs: the single-writer actor already serializes every
            // send/shield, so a competing spend of the selected UTXOs can't be built
            // concurrently (an operation racing a later send fails cleanly instead).
            None,
        )
        .map_err(|e| {
            use zcash_client_backend::data_api::error::Error as WalletError;
            match &e {
                WalletError::InsufficientFunds {
                    available,
                    required,
                } => RpcError::insufficient_funds(format!(
                    "Insufficient coinbase funds: {} zatoshis available, {} required \
                     (including fee)",
                    u64::from(*available),
                    u64::from(*required),
                ))
                .with_details(ErrorDetails::InsufficientFunds(
                    InsufficientFunds {
                        available: Some(u64::from(*available)),
                        required: Some(u64::from(*required)),
                        ..Default::default()
                    },
                )),
                _ => {
                    let s = e.to_string();
                    if s.to_lowercase().contains("insufficient") {
                        RpcError::insufficient_funds(s)
                    } else {
                        RpcError::wallet(s)
                    }
                }
            }
        })?;

        let (shielding_utxos, shielding_value) = {
            let inputs = proposal.steps().head.transparent_inputs();
            (
                inputs.len() as u64,
                inputs
                    .iter()
                    .map(|i| u64::from(i.txout().value()))
                    .sum::<u64>(),
            )
        };

        Ok(crate::wallet::ShieldCoinbasePlan {
            proposal,
            shielding_utxos,
            shielding_value,
            remaining_utxos: eligible_count.saturating_sub(shielding_utxos),
            remaining_value: eligible_value.saturating_sub(shielding_value),
        })
    }

    /// Execute a `z_shieldcoinbase` proposal: prove, sign (transparent inputs + shielded
    /// outputs), store (which locks the spent UTXOs against double-spend and keeps the raw bytes
    /// for the rebroadcast loop), and broadcast. Runs on the actor under the operation's opid,
    /// serialized with every other send. Uses the fused `create_proposed_transactions` path -
    /// coinbase shielding is rare enough that the per-send proving-key rebuild is acceptable.
    async fn do_execute_shield_coinbase(
        &mut self,
        proposal: Proposal<StandardFeeRule, Infallible>,
    ) -> Result<TxId, RpcError> {
        self.relock_if_expired();
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        let usk = seed_guard(&self.seed).derive_usk(self.network, account_index)?;

        let net = self.network;
        let prover: &LocalTxProver = &self.prover;
        let db = &mut self.db_data;
        let (txid, raw): (TxId, Vec<u8>) =
            tokio::task::block_in_place(move || -> Result<_, RpcError> {
                // The `Infallible` turbofish parameters pin the phantom input-selection and
                // change-strategy error types (this proposal was built without either).
                let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
                    db,
                    &net,
                    prover,
                    prover,
                    &SpendingKeys::from_unified_spending_key(usk),
                    OvkPolicy::Sender,
                    &proposal,
                    // `None` keeps the builder-derived expiry from the proposal's target
                    // height, matching the fused send path.
                    None,
                )
                .map_err(|e| {
                    let s = e.to_string();
                    if s.to_lowercase().contains("insufficient") {
                        RpcError::insufficient_funds(s)
                    } else {
                        RpcError::wallet(s)
                    }
                })?;
                if txids.len() > 1 {
                    return Err(RpcError::wallet(
                        "multi-transaction proposals are not supported",
                    ));
                }
                let txid = *txids.first();
                let raw = read_raw_tx(db, txid)?;
                Ok((txid, raw))
            })?;

        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        info!("z_shieldcoinbase broadcast {txid}");
        Ok(txid)
    }

    /// Build a `z_mergetoaddress` plan: fix the input selection (non-coinbase transparent UTXOs
    /// or shielded notes - one class per merge), compute the exact ZIP-317 fee, and return the
    /// work plus the merging/remaining stats. The payment is `inputs - fee` with **no change in
    /// any pool** (a merge pays everything it selects to one destination), so like
    /// `z_shieldcoinbase` the whole selection is fixed here in the synchronous half and a send
    /// racing the opid fails cleanly at execute.
    ///
    /// Selection is **smallest-first** (a documented zecd choice; zcashd does not specify an
    /// order): a merge exists to eliminate outputs, and taking the smallest removes the most
    /// per round under a count limit. Shielded selection is additionally restricted to **one
    /// pool family per call** when a limit binds (Sapling, or Orchard+Ironwood together) so the
    /// hand-computed fee stays a faithful specialization of librustzcash's `propose_send_max`;
    /// repeated calls drain the other family. When no limit binds, the whole proposal is
    /// delegated to librustzcash's `propose_send_max_transfer` and none of zecd's fee math runs.
    async fn do_propose_merge_to_address(
        &mut self,
        source: MergeSource,
        to_address: zcash_address::ZcashAddress,
        memo: Option<zcash_protocol::memo::MemoBytes>,
        transparent_limit: Option<usize>,
        shielded_limit: Option<usize>,
        privacy: SendPrivacy,
    ) -> Result<MergePlan, RpcError> {
        use std::collections::BTreeMap;

        // Fail a locked or watch-only wallet synchronously (zcashd errors before returning an
        // opid); the derived key is dropped - execution re-derives its own.
        self.relock_if_expired();
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        let _ = seed_guard(&self.seed).derive_usk(self.network, account_index)?;

        // Authoritative privacy gates for a transparent source, mirroring `do_send`'s (the RPC
        // layer rejects both synchronously with the same errors; re-checking keeps the actor
        // sound against any future caller). The `FullPrivacy` no-cross-pool rule is enforced on
        // the built proposal below, where the input pools are known.
        if matches!(source, MergeSource::Transparent(_)) && !privacy.allows_transparent_inputs() {
            return Err(insufficient_privacy_for_transparent_sender(privacy));
        }

        // Same tip catch-up as a send: the plan's target height (and thus the eventual tx's
        // expiry) must come from the real chain tip, not a lagging scanned height.
        self.sync_to_tip_for_send().await;

        let account_id = self.require_account()?;
        let net = self.network;
        let policy = self.confirmations_policy;
        let orchard_action_limit = self.orchard_action_limit;
        let db = &mut self.db_data;

        let (target_height, anchor_height) = db
            .get_target_and_anchor_heights(policy.trusted())
            .map_err(RpcError::database_internal)?
            .ok_or_else(|| {
                RpcError::wallet("wallet has no chain tip yet; cannot build a transaction")
            })?;
        let ironwood_active =
            net.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from(target_height));

        // Destination classification. The RPC layer already validated the encoding; a bare
        // transparent destination keeps the whole merge transparent (t→t) or pays a shielded
        // merge out transparently (z→t), anything else resolves to one shielded output pool.
        let dest_addr: Address = to_address
            .clone()
            .convert_if_network::<Address>(net.network_type())
            .map_err(|e| {
                RpcError::invalid_parameter(format!(
                    "Invalid parameter, unknown address format: {e}"
                ))
            })?;
        let dest_transparent: Option<TransparentAddress> = match &dest_addr {
            Address::Transparent(t) => Some(*t),
            _ => None,
        };

        match source {
            MergeSource::Transparent(addrs) => {
                let receivers = db
                    .get_transparent_receivers(account_id, true, true)
                    .map_err(RpcError::database_internal)?;
                let from_addrs: Vec<TransparentAddress> = match addrs {
                    None => receivers.keys().copied().collect(),
                    Some(list) => {
                        for a in &list {
                            if !receivers.contains_key(a) {
                                return Err(RpcError::invalid_address_or_key(
                                    "Invalid from address, no payment source found for address.",
                                ));
                            }
                        }
                        list
                    }
                };
                let mut utxos: Vec<WalletTransparentOutput<AccountUuid>> = Vec::new();
                for addr in &from_addrs {
                    utxos.extend(
                        db.get_spendable_transparent_outputs(
                            addr,
                            target_height,
                            policy,
                            // A merge either emits a transparent output (t→t) or is the general
                            // t→z sweep; either way coinbase stays `z_shieldcoinbase`'s alone.
                            CoinbaseFilter::NonCoinbaseOnly,
                            // zecd never locks inputs, so lock state can't exclude anything.
                            LockFilter::Unfiltered,
                        )
                        .map_err(RpcError::database_internal)?,
                    );
                }
                let eligible_count = utxos.len() as u64;
                let eligible_value: u64 = utxos.iter().map(|u| u64::from(u.value())).sum();
                if utxos.is_empty() {
                    return Err(RpcError::insufficient_funds(
                        "Could not find any funds to merge.",
                    ));
                }
                // Smallest-first (outpoint tiebreak for determinism), then the count limit and
                // the block-space cap.
                utxos.sort_by_key(|u| (u.value(), *u.outpoint().hash(), u.outpoint().n()));
                utxos.truncate(
                    transparent_limit
                        .unwrap_or(usize::MAX)
                        .min(MERGE_MAX_TRANSPARENT_INPUTS),
                );
                let merging_count = utxos.len() as u64;
                let merging_value: u64 = utxos.iter().map(|u| u64::from(u.value())).sum();

                // Transparent inputs plus a transparent destination is a fully transparent
                // transaction (zcashd's split between `AllowRevealedSenders` and
                // `AllowFullyTransparent`); re-checked here like the source gate above.
                if dest_transparent.is_some() && privacy != SendPrivacy::AllowFullyTransparent {
                    return Err(insufficient_privacy_for_fully_transparent());
                }

                let work = if let Some(to_t) = dest_transparent {
                    // t→t: exact ZIP-317 fee for n P2PKH inputs and one transparent output,
                    // matching the transaction `Builder`'s own arithmetic (see
                    // `select_transparent_inputs`; there is no change output here).
                    let fee_rule = Zip317FeeRule::standard();
                    let fee = merge_transparent_fee(
                        utxos.len(),
                        transparent_txout_size(&to_t),
                        fee_rule.p2pkh_standard_output_size(),
                        u64::from(fee_rule.marginal_fee()),
                        fee_rule.grace_actions(),
                    );
                    let amount = merging_value
                        .checked_sub(fee)
                        .filter(|a| *a > 0)
                        .ok_or_else(|| {
                            RpcError::insufficient_funds(format!(
                                "Insufficient funds: {merging_value} zatoshis selected, \
                                 {fee} required (including fee)"
                            ))
                        })?;
                    MergeWork::TransparentTx {
                        inputs: utxos,
                        to: to_t,
                        amount: Zatoshis::from_u64(amount)
                            .map_err(|e| RpcError::misc(format!("merge amount: {e}")))?,
                        fee: Zatoshis::from_u64(fee)
                            .map_err(|e| RpcError::misc(format!("merge fee: {e}")))?,
                    }
                } else {
                    // t→z: a hand-built single-step proposal, the general-funds analogue of
                    // librustzcash's `propose_shielding_coinbase` (transparent inputs, one
                    // shielded payment of `inputs - fee`, no change), executed via the fused
                    // path which signs the transparent inputs from the USK.
                    let dest_pool = merge_shielded_destination_pool(&dest_addr, ironwood_active)?;
                    let (sapling_out, orchard_act, ironwood_act) =
                        merge_action_counts(&net, target_height, dest_pool, 0, 0, 0)?;
                    let fee = StandardFeeRule::Zip317
                        .fee_required(
                            &net,
                            BlockHeight::from(target_height),
                            utxos
                                .iter()
                                .map(transparent_fees::InputView::serialized_size),
                            std::iter::empty::<usize>(),
                            0,
                            sapling_out,
                            orchard_act,
                            ironwood_act,
                        )
                        .map_err(|e| RpcError::wallet(format!("fee computation failed: {e}")))?;
                    let input_total = Zatoshis::from_u64(merging_value)
                        .map_err(|e| RpcError::misc(format!("merge input total: {e}")))?;
                    let payment_amount = (input_total - fee)
                        .filter(|a| *a > Zatoshis::ZERO)
                        .ok_or_else(|| {
                            RpcError::insufficient_funds(format!(
                                "Insufficient funds: {} zatoshis selected, {} required \
                                 (including fee)",
                                u64::from(input_total),
                                u64::from(fee),
                            ))
                        })?;
                    let payment = zip321::Payment::new(
                        to_address.clone(),
                        Some(payment_amount),
                        memo,
                        None,
                        None,
                        vec![],
                    )
                    .map_err(|e| RpcError::invalid_parameter(format!("invalid payment: {e}")))?;
                    let request = TransactionRequest::new(vec![payment])
                        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e}")))?;
                    let mut payment_pools = BTreeMap::new();
                    payment_pools.insert(0usize, dest_pool);
                    // Rebuild the inputs in the account-agnostic shape a proposal carries
                    // (`WalletTransparentOutput<()>`; the redaction upstream applies itself).
                    let t_inputs: Vec<WalletTransparentOutput<()>> = utxos
                        .iter()
                        .map(|u| {
                            WalletTransparentOutput::from_parts(
                                u.outpoint().clone(),
                                u.txout().clone(),
                                u.mined_height(),
                                u.recipient_account().map(|_| ()),
                                u.recipient_key_scope(),
                                None,
                            )
                            .ok_or_else(|| {
                                RpcError::wallet("owned transparent UTXO has no known script form")
                            })
                        })
                        .collect::<Result<_, _>>()?;
                    let balance = TransactionBalance::new(vec![], fee)
                        .map_err(|_| RpcError::misc("merge fee overflows".to_string()))?;
                    let proposal = Proposal::single_step(
                        request,
                        payment_pools,
                        t_inputs,
                        None,
                        anchor_height,
                        balance,
                        StandardFeeRule::Zip317,
                        target_height,
                        policy,
                        // `is_shielding = true` is reserved for the "no payment, all value in
                        // change" shape of `propose_shielding`; this is an explicit payment.
                        false,
                        ironwood_active,
                    )
                    .map_err(|e| RpcError::wallet(format!("merge proposal invalid: {e}")))?;
                    enforce_orchard_action_limit(&proposal, orchard_action_limit)?;
                    MergeWork::UtxoProposal(proposal)
                };

                Ok(MergePlan {
                    work,
                    merging_utxos: merging_count,
                    merging_transparent_value: merging_value,
                    merging_notes: 0,
                    merging_shielded_value: 0,
                    remaining_utxos: eligible_count.saturating_sub(merging_count),
                    remaining_transparent_value: eligible_value.saturating_sub(merging_value),
                    remaining_notes: 0,
                    remaining_shielded_value: 0,
                })
            }
            MergeSource::Shielded(pools) => {
                let notes = db
                    .select_spendable_notes(
                        account_id,
                        TargetValue::AllFunds(MaxSpendMode::MaxSpendable),
                        &pools,
                        target_height,
                        policy,
                        &[],
                        LockFilter::Unfiltered,
                    )
                    .map_err(RpcError::database_internal)?;
                let sapling_n = notes.sapling().len();
                let orchard_family_n = notes.orchard().len() + notes.ironwood().len();
                let eligible_count = (sapling_n + orchard_family_n) as u64;
                let eligible_value = u64::from(
                    notes
                        .total_value()
                        .map_err(|e| RpcError::misc(format!("note value overflow: {e:?}")))?,
                );
                if eligible_count == 0 {
                    return Err(RpcError::insufficient_funds(
                        "Could not find any funds to merge.",
                    ));
                }

                let limit = shielded_limit.unwrap_or(usize::MAX);
                // The Orchard-family action cap: one payment output at most, so the family's
                // proposal actions = max(spends, 1) = spends; `enforce_orchard_action_limit`
                // runs on the built proposal as a backstop.
                let family_fits_action_limit =
                    orchard_action_limit == 0 || orchard_family_n <= orchard_action_limit;

                if sapling_n + orchard_family_n <= limit && family_fits_action_limit {
                    // No limit binds: delegate the whole proposal (selection, fee, pool
                    // routing, TEX rejection) to librustzcash's send-max primitive.
                    let proposal = propose_send_max_transfer::<_, _, _, Infallible>(
                        db,
                        &net,
                        account_id,
                        &pools,
                        &StandardFeeRule::Zip317,
                        to_address.clone(),
                        memo,
                        MaxSpendMode::MaxSpendable,
                        policy,
                        &LockedInputPolicy::default(),
                        // zecd does not lock inputs: the single-writer actor serializes sends.
                        None,
                    )
                    .map_err(|e| {
                        let s = e.to_string();
                        if s.to_lowercase().contains("insufficient") {
                            RpcError::insufficient_funds(s)
                        } else {
                            RpcError::wallet(s)
                        }
                    })?;
                    // The input pools are only known now: enforce FullPrivacy's no-cross-pool
                    // rule (and the action-limit backstop) on the built proposal, as `do_send`
                    // does.
                    if privacy == SendPrivacy::FullPrivacy {
                        enforce_full_privacy(&proposal)?;
                    }
                    enforce_orchard_action_limit(&proposal, orchard_action_limit)?;
                    Ok(MergePlan {
                        work: MergeWork::NoteProposal(proposal),
                        merging_utxos: 0,
                        merging_transparent_value: 0,
                        merging_notes: eligible_count,
                        merging_shielded_value: eligible_value,
                        remaining_utxos: 0,
                        remaining_transparent_value: 0,
                        remaining_notes: 0,
                        remaining_shielded_value: 0,
                    })
                } else {
                    // A limit binds: manual truncated selection, one pool family per call (the
                    // family holding more notes), smallest-first within it.
                    let family_is_sapling = sapling_n >= orchard_family_n;
                    let cap = if family_is_sapling {
                        limit
                    } else if orchard_action_limit > 0 {
                        limit.min(orchard_action_limit)
                    } else {
                        limit
                    };
                    let mut fam: Vec<_> = notes
                        .into_vec(&RetainAllNotes)
                        .into_iter()
                        .filter(|n| {
                            let orchard_family = matches!(
                                n.note().pool(),
                                ShieldedPool::Orchard | ShieldedPool::Ironwood
                            );
                            family_is_sapling != orchard_family
                        })
                        .collect();
                    fam.sort_by_key(|n| u64::from(n.note().value()));
                    fam.truncate(cap);
                    let merging_count = fam.len() as u64;
                    let merging_value: u64 = fam.iter().map(|n| u64::from(n.note().value())).sum();
                    let sapling_spends = fam
                        .iter()
                        .filter(|n| n.note().pool() == ShieldedPool::Sapling)
                        .count();
                    let orchard_spends = fam
                        .iter()
                        .filter(|n| n.note().pool() == ShieldedPool::Orchard)
                        .count();
                    let ironwood_spends = fam
                        .iter()
                        .filter(|n| n.note().pool() == ShieldedPool::Ironwood)
                        .count();

                    let (dest_pool, out_sizes): (PoolType, Vec<usize>) = match dest_transparent {
                        Some(t) => (PoolType::Transparent, vec![transparent_txout_size(&t)]),
                        None => (
                            merge_shielded_destination_pool(&dest_addr, ironwood_active)?,
                            vec![],
                        ),
                    };
                    let (sapling_out, orchard_act, ironwood_act) = merge_action_counts(
                        &net,
                        target_height,
                        dest_pool,
                        sapling_spends,
                        orchard_spends,
                        ironwood_spends,
                    )?;
                    let fee = StandardFeeRule::Zip317
                        .fee_required(
                            &net,
                            BlockHeight::from(target_height),
                            std::iter::empty(),
                            out_sizes,
                            sapling_spends,
                            sapling_out,
                            orchard_act,
                            ironwood_act,
                        )
                        .map_err(|e| RpcError::wallet(format!("fee computation failed: {e}")))?;
                    let input_total = Zatoshis::from_u64(merging_value)
                        .map_err(|e| RpcError::misc(format!("merge input total: {e}")))?;
                    let payment_amount = (input_total - fee)
                        .filter(|a| *a > Zatoshis::ZERO)
                        .ok_or_else(|| {
                            RpcError::insufficient_funds(format!(
                                "Insufficient funds: {} zatoshis selected, {} required \
                                 (including fee)",
                                u64::from(input_total),
                                u64::from(fee),
                            ))
                        })?;
                    let payment = zip321::Payment::new(
                        to_address.clone(),
                        Some(payment_amount),
                        memo,
                        None,
                        None,
                        vec![],
                    )
                    .map_err(|e| RpcError::invalid_parameter(format!("invalid payment: {e}")))?;
                    let request = TransactionRequest::new(vec![payment])
                        .map_err(|e| RpcError::wallet(format!("invalid payment request: {e}")))?;
                    let mut payment_pools = BTreeMap::new();
                    payment_pools.insert(0usize, dest_pool);
                    let shielded_inputs = ShieldedInputs::from_parts(
                        NonEmpty::from_vec(fam)
                            .ok_or_else(|| RpcError::misc("empty merge selection".to_string()))?,
                    );
                    let balance = TransactionBalance::new(vec![], fee)
                        .map_err(|_| RpcError::misc("merge fee overflows".to_string()))?;
                    let proposal = Proposal::single_step(
                        request,
                        payment_pools,
                        vec![],
                        Some(shielded_inputs),
                        anchor_height,
                        balance,
                        StandardFeeRule::Zip317,
                        target_height,
                        policy,
                        false,
                        ironwood_active,
                    )
                    .map_err(|e| RpcError::wallet(format!("merge proposal invalid: {e}")))?;
                    if privacy == SendPrivacy::FullPrivacy {
                        enforce_full_privacy(&proposal)?;
                    }
                    enforce_orchard_action_limit(&proposal, orchard_action_limit)?;

                    Ok(MergePlan {
                        work: MergeWork::NoteProposal(proposal),
                        merging_utxos: 0,
                        merging_transparent_value: 0,
                        merging_notes: merging_count,
                        merging_shielded_value: merging_value,
                        remaining_utxos: 0,
                        remaining_transparent_value: 0,
                        remaining_notes: eligible_count.saturating_sub(merging_count),
                        remaining_shielded_value: eligible_value.saturating_sub(merging_value),
                    })
                }
            }
        }
    }

    /// Execute a `z_mergetoaddress` plan: prove/sign/store/broadcast the fixed work. Proposal
    /// shapes ride the fused `create_proposed_transactions` path (which signs transparent
    /// inputs from the USK and proves shielded spends - merges are rare enough that the
    /// per-send proving-key rebuild is acceptable, exactly as for `z_shieldcoinbase`); the
    /// fully-transparent t→t shape uses the native transparent builder with **no change**
    /// output. Runs on the actor under the operation's opid, serialized with every other send.
    async fn do_execute_merge_to_address(&mut self, work: MergeWork) -> Result<TxId, RpcError> {
        self.relock_if_expired();
        let account_index = self.account_index.ok_or_else(private_keys_disabled)?;
        let usk = seed_guard(&self.seed).derive_usk(self.network, account_index)?;

        let net = self.network;
        let (txid, raw): (TxId, Vec<u8>) = match work {
            MergeWork::UtxoProposal(proposal) => {
                let prover: &LocalTxProver = &self.prover;
                let db = &mut self.db_data;
                tokio::task::block_in_place(move || -> Result<_, RpcError> {
                    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
                        db,
                        &net,
                        prover,
                        prover,
                        &SpendingKeys::from_unified_spending_key(usk),
                        OvkPolicy::Sender,
                        &proposal,
                        None,
                    )
                    .map_err(classify_merge_execute_err)?;
                    if txids.len() > 1 {
                        return Err(RpcError::wallet(
                            "multi-transaction proposals are not supported",
                        ));
                    }
                    let txid = *txids.first();
                    let raw = read_raw_tx(db, txid)?;
                    Ok((txid, raw))
                })?
            }
            MergeWork::NoteProposal(proposal) => {
                let prover: &LocalTxProver = &self.prover;
                let db = &mut self.db_data;
                tokio::task::block_in_place(move || -> Result<_, RpcError> {
                    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
                        db,
                        &net,
                        prover,
                        prover,
                        &SpendingKeys::from_unified_spending_key(usk),
                        OvkPolicy::Sender,
                        &proposal,
                        None,
                    )
                    .map_err(classify_merge_execute_err)?;
                    if txids.len() > 1 {
                        return Err(RpcError::wallet(
                            "multi-transaction proposals are not supported",
                        ));
                    }
                    let txid = *txids.first();
                    let raw = read_raw_tx(db, txid)?;
                    Ok((txid, raw))
                })?
            }
            MergeWork::TransparentTx {
                inputs,
                to,
                amount,
                fee,
            } => {
                let account_id = self.require_account()?;
                let prover: &LocalTxProver = &self.prover;
                let db = &mut self.db_data;
                let (target_height, _anchor) = db
                    .get_target_and_anchor_heights(std::num::NonZeroU32::MIN)
                    .map_err(RpcError::database_internal)?
                    .ok_or_else(|| {
                        RpcError::wallet("wallet has no chain tip yet; cannot build a transaction")
                    })?;
                let recipients = [(to, amount)];
                tokio::task::block_in_place(move || -> Result<_, RpcError> {
                    build_signed_transparent_tx(
                        db,
                        net,
                        target_height,
                        &usk,
                        account_id,
                        &inputs,
                        &recipients,
                        // A merge pays out `inputs - fee`: no change output by construction.
                        None,
                        fee,
                        prover,
                    )
                })?
            }
        };

        // Every merge shape can consume transparent UTXOs the engine's input matcher watches
        // (t→t and t→z always do), so refresh the watch set before the next scan.
        self.transparent_unspent_dirty = true;
        self.broadcast_committed(txid, raw).await?;
        self.update_status();
        info!("z_mergetoaddress broadcast {txid}");
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
                    "created {txid} but no upstream is reachable ({e}); it will be \
                     re-broadcast once a connection recovers"
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
                info!("upstream already has {txid}; treating broadcast as delivered");
                return Ok(());
            }
            // An explicit upstream rejection (the node examined the tx and refused it) is a
            // different case from a transport failure: surface it as -26. The tx's notes stay
            // locked in the wallet until its expiry height, after which they become spendable
            // again - an immediate retry fails with -6 rather than double-paying.
            let reason = sanitize_upstream_msg(&outcome.error_message);
            warn!(
                "upstream rejected {txid} (code {}): {reason}",
                outcome.error_code
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
                .map_err(|e| upstream_error(e, "could not connect to the upstream node"))?;
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
                // `mark_disconnected` logs the detail server-side; the client gets a generic
                // message so the upstream endpoint in `e` is not leaked.
                self.mark_disconnected(format!("transaction fetch failed: {e}"));
                self.update_status();
                Err(RpcError::misc(
                    "transaction fetch from the upstream node failed",
                ))
            }
        }
    }

    /// Query the upstream for evidence of every tx touching a transparent address in
    /// `[start, end]` (zebra `getaddresstxids`; lightwalletd `GetTaddressTxids`). A transport
    /// failure drops the client (so the next op reconnects) and surfaces as `Err`; an unseen
    /// address simply yields an empty list.
    async fn fetch_transparent_tx_evidence(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> Result<Vec<TxEvidence>, RpcError> {
        if self.client.is_none() {
            self.connect()
                .await
                .map_err(|e| upstream_error(e, "could not connect to the upstream node"))?;
        }
        let result = {
            let client = self
                .client
                .as_mut()
                .ok_or_else(|| RpcError::misc("not connected to upstream"))?;
            tokio::time::timeout(
                UNARY_RPC_TIMEOUT,
                client.transparent_tx_evidence(addresses, start, end),
            )
            .await
            .map_err(|_| anyhow!("address-txid query timed out after {UNARY_RPC_TIMEOUT:?}"))
            .and_then(|r| r)
        };
        match result {
            Ok(txids) => Ok(txids),
            Err(e) => {
                // `mark_disconnected` logs the detail server-side; the client gets a generic
                // message so the upstream endpoint in `e` is not leaked.
                self.mark_disconnected(format!("transparent txid query failed: {e}"));
                self.update_status();
                Err(RpcError::misc(
                    "transparent address-index query to the upstream node failed",
                ))
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
                .map_err(|e| upstream_error(e, "could not connect to the upstream node"))?;
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
                // `mark_disconnected` logs the detail server-side; the client gets a generic
                // message so the upstream endpoint in `e` is not leaked.
                self.mark_disconnected(format!("transaction broadcast failed: {e}"));
                self.update_status();
                return Err(RpcError::misc(
                    "transaction broadcast to the upstream node failed",
                ));
            }
        };
        let result = classify_broadcast_outcome(&outcome);
        match &result {
            // Accepted-but-not-fresh is the idempotent already-in-mempool case (worth a note).
            Ok(()) if !outcome.is_accepted() => {
                info!("upstream already has tx in mempool; sendrawtransaction succeeds")
            }
            Err(e) if e.code == codes::RPC_VERIFY_REJECTED => warn!(
                "upstream rejected tx (code {}): {}",
                outcome.error_code, e.message
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
        // Seed exposure is audit material, like the auto-unlock and relock events. The
        // passphrase itself never appears anywhere near a log.
        info!(
            target: "zecd::audit",
            timeout_secs,
            "wallet unlocked via walletpassphrase"
        );
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
    transparent_enabled: bool,
    roots_synced: &mut bool,
    budget: Duration,
) -> anyhow::Result<ServerInfo> {
    tokio::time::timeout(budget, async {
        let info = verify_server_network(client, network).await?;
        if let Some(why) = transparent_capability_error(
            transparent_enabled,
            client.block_scan_covers_transparent(),
        ) {
            return Err(anyhow!("{why}"));
        }
        if !*roots_synced {
            engine::update_subtree_roots(client, db_data).await?;
            *roots_synced = true;
        }
        Ok::<ServerInfo, anyhow::Error>(info)
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
/// reports one. On success the fetched [`ServerInfo`] is returned so the caller can also
/// inspect the upstream's reported network upgrades (the outdated-build detector).
async fn verify_server_network<C: ChainSource>(
    client: &mut C,
    network: ZNetwork,
) -> anyhow::Result<ServerInfo> {
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
    Ok(info)
}

/// Classify a lightwalletd `chain_name` as mainnet (`Some(true)`), a test chain
/// (`Some(false)`), or unrecognized (`None`).
pub(crate) fn chain_name_is_main(chain_name: &str) -> Option<bool> {
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

/// Whether any recipient in `request` forces a **Sapling output**: a shielded address carrying a
/// Sapling receiver but *no* Orchard receiver (a bare `zs…`, or a UA whose only shielded receiver
/// is Sapling). This is the sole way a send on the Orchard-only cached PCZT path produces a PCZT
/// with a non-empty Sapling bundle - spends are always Orchard and change goes to Orchard (Sapling
/// isn't an enabled pool on that path, or `cached_pczt_path` is already false). The PCZT extractor
/// (`extract_and_store_transaction_from_pczt`) rejects such a bundle without a Sapling *verifying*
/// key, and the cached path passes none - so `do_send`/`begin_or_queue_send` divert these sends to
/// the fused `create_proposed_transactions` path, which builds, proves, and verifies Sapling
/// outputs itself. A dual Orchard+Sapling UA is deliberately *not* flagged: an Orchard-only wallet
/// routes the payment to the UA's Orchard receiver, so no Sapling output is produced. Keyed off the
/// recipient address (not the built proposal) so the routing decision is made before any build; on
/// this path that is equivalent, since a Sapling-only recipient is the only Sapling-output source.
fn request_pays_sapling_output(net: &ZNetwork, request: &TransactionRequest) -> bool {
    let net_type = net.network_type();
    request.payments().values().any(|p| {
        match p
            .recipient_address()
            .clone()
            .convert_if_network::<Address>(net_type)
        {
            Ok(addr) => {
                crate::address::has_shielded_receiver(&addr)
                    && !crate::address::has_orchard_receiver(&addr)
            }
            // Unparseable on this network (already rejected at the RPC layer): don't reroute; the
            // normal build path surfaces the error.
            Err(_) => false,
        }
    })
}

/// Whether any payment in `request` targets an address with no shielded receiver (a bare
/// transparent recipient, forcing a transparent output). Used to gate a transparent *source*:
/// transparent inputs plus a transparent output is a fully transparent transaction, which
/// requires `AllowFullyTransparent` even when the change would shield (zcashd's split between
/// `AllowRevealedSenders` and `AllowFullyTransparent`). Unlike `transparent_only_recipients`
/// this flags a *mixed* request too (one transparent recipient among shielded ones), which
/// falls past that all-transparent check onto the proposal path.
fn request_pays_transparent_output(net: &ZNetwork, request: &TransactionRequest) -> bool {
    let net_type = net.network_type();
    request.payments().values().any(|p| {
        match p
            .recipient_address()
            .clone()
            .convert_if_network::<Address>(net_type)
        {
            Ok(addr) => !crate::address::has_shielded_receiver(&addr),
            // Unparseable on this network (already rejected at the RPC layer): don't gate; the
            // normal build path surfaces the error.
            Err(_) => false,
        }
    })
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
    // Ironwood (V6) proof step. A post-NU6.3 transaction carries a separate Ironwood bundle needing
    // its own proof (mirrors devtool's `pczt/prove.rs`). The Ironwood bundle uses the
    // **`PostNu6_3`** circuit (orchard `bundle.rs`), so it must be proved with the `PostNu6_3` key -
    // `Bundle::create_proof` rejects a `FixedPostNu6_2` key here. That key is
    // `ProvingKeyCache::ironwood_pk`, built at startup whenever the network can activate NU6.3 (so
    // it is always present when `requires_ironwood_proof()` is true; its absence would mean NU6.3
    // fired without the cache expecting it, which is a bug worth surfacing).
    let prover = if prover.requires_ironwood_proof() {
        let ironwood_pk = keys.ironwood_pk.as_ref().ok_or_else(|| {
            RpcError::wallet(
                "Ironwood proof required but the PostNu6_3 proving key was not built \
                 (NU6.3 not expected on this network)",
            )
        })?;
        prover
            .create_ironwood_proof(ironwood_pk)
            .map_err(|e| RpcError::wallet(format!("Ironwood proof generation failed: {e:?}")))?
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
    // Spend authorization for the Ironwood (V6) bundle - a separate bundle from Orchard, so its
    // spends need their own signing pass or `extract_and_store_transaction_from_pczt` fails with
    // `Ironwood(Extract(MissingSpendAuthSig))`. Ironwood reuses Orchard's spend crypto, so the same
    // Orchard `ask` signs it; the loop mirrors the Orchard one (skip the dummy-spend
    // `WrongSpendAuthorizingKey`, stop at `InvalidIndex`). A pre-NU6.3 send has no Ironwood bundle,
    // so `sign_ironwood(0, ..)` returns `InvalidIndex` immediately and the loop is a no-op.
    {
        let mut index = 0;
        loop {
            match signer.sign_ironwood(index, &ask) {
                Ok(())
                | Err(SignerError::IronwoodSign(
                    orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                )) => index += 1,
                Err(SignerError::InvalidIndex) => break,
                Err(e) => {
                    return Err(RpcError::wallet(format!(
                        "Ironwood spend signing failed: {e:?}"
                    )))
                }
            }
        }
    }
    Ok(signer.finish())
}

/// Finalize + persist a proven, signed PCZT (phase C): records the tx, its spends/change, and
/// marks inputs spent - the same wallet bookkeeping `create_proposed_transactions` does. A DB
/// write, so it runs on the single-writer actor. The Sapling verifying key is `None` because this
/// path is only reached for sends with **no Sapling output** - the extractor rejects a Sapling
/// bundle without one, so `do_send`/`begin_or_queue_send` divert any send to a Sapling-only
/// recipient to the fused path before reaching here (the guard is `request_pays_sapling_output`).
/// Note this is about Sapling *outputs*, not spends: zecd never spends Sapling notes on this path,
/// but a send can still *pay* a Sapling recipient. `N` (the note-ref type) is otherwise
/// unconstrained here - it only appears in the error type - so pin it to our `WalletDb`'s note ref,
/// as `ProposalError` does for the fused path.
///
/// Orchard verifying key: **always `None`**. The extractor verifies *both* the Orchard and the
/// Ironwood bundles through that one argument, but they use different circuit versions
/// (`FixedPostNu6_2` vs `PostNu6_3`), so no single key can cover a post-NU6.3 send carrying both -
/// and passing `None` makes the extractor generate the right verifying key *per bundle* from each
/// bundle's own version (a `keygen_vk`, cheaper than the proving keygen). zecd used to cache the
/// `FixedPostNu6_2` key and pass it for the Ironwood-free case, but NU6.3 is live on both public
/// networks, so every send now carries an Ironwood bundle and that cache went unread while costing
/// ~1.2 s of every startup. The one path that still hits the on-the-fly `keygen_vk` for an Orchard
/// V2 bundle is a pre-NU6.3 chain, i.e. a regtest chain started without
/// `ZECD_REGTEST_NU63_HEIGHT`.
///
/// The Ironwood bundle's own outputs are recorded by the extractor as of `zcash_client_backend
/// 0.24.0-rc.7`. Through rc.6 it built its `SentTransaction` outputs from the Sapling and Orchard
/// bundles only, so a post-NU6.3 send's payment and change - which ride the Ironwood bundle -
/// landed with no `sent_notes` row and no memo, and nothing downstream repaired it on the authoring
/// node (the compact scan materializes the notes but carries no memos, and enhancement skips a tx
/// whose raw bytes the send pre-stored). zecd covered that by re-decrypting the just-stored
/// transaction here; the pass is gone with the version that made it unnecessary.
fn store_pczt(db: &mut WriteDb, pczt: pczt::Pczt) -> Result<TxId, RpcError> {
    extract_and_store_transaction_from_pczt::<_, zcash_client_sqlite::ReceivedNoteId>(
        db, pczt, None, None,
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
fn log_send_latency(
    path: &str,
    shape: SendShape,
    build: Duration,
    prove: Duration,
    store: Duration,
    broadcast: Duration,
) {
    // Fields, not prose: this is the line an operator graphs, so each phase duration and the
    // proposal shape must be queryable without a log parser.
    info!(
        path,
        inputs = shape.inputs,
        orchard_actions = shape.orchard_actions,
        build_ms = build.as_millis() as u64,
        prove_ms = prove.as_millis() as u64,
        store_ms = store.as_millis() as u64,
        broadcast_ms = broadcast.as_millis() as u64,
        "send complete"
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
/// has any transparent component, or if it touches **more than one** shielded pool (a turnstile
/// crossing, which reveals the crossed amount on-chain via `valueBalance`).
///
/// Ironwood counts as its own pool here, not as a flavour of Orchard. It is a distinct value pool
/// (`PoolType::IRONWOOD`), so moving value between it and Sapling or Orchard crosses a turnstile
/// exactly like Sapling<->Orchard does. Note this is deliberately *not* the same grouping upstream
/// uses to select inputs, where {Sapling, Ironwood} is one group: that grouping is about which
/// notes can fund one transaction, and says nothing about whether the resulting transaction leaks
/// an amount. Collapsing the two - counting a Sapling output funded from ironwood notes as
/// single-pool - is what let FullPrivacy pass an amount-revealing send.
fn single_pool_violated(transparent: bool, sapling: bool, orchard: bool, ironwood: bool) -> bool {
    transparent || [sapling, orchard, ironwood].iter().filter(|p| **p).count() > 1
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
        let ironwood = step.involves(PoolType::IRONWOOD);
        if single_pool_violated(transparent, sapling, orchard, ironwood) {
            return Err(RpcError::invalid_parameter(
                "Privacy policy FullPrivacy rejects this send: it would leave a single shielded \
                 pool (a transparent component, or a crossing between two shielded pools - \
                 Sapling, Orchard or Ironwood - that reveals the transferred amount on-chain). \
                 Set [spend] privacy_policy = \"AllowRevealedRecipients\" to permit this.",
            ));
        }
    }
    Ok(())
}

/// Orchard actions a single proposal step contributes: `max(orchard inputs, orchard outputs)`,
/// since each Orchard action carries one spend and one output (a dummy filling whichever side is
/// short). Mirrors the count Zallet's `orchard_actions` limit checks. `orchard_outputs` counts
/// both payment outputs landing in the Orchard pool and Orchard change notes.
///
/// Ironwood (V3) actions are Orchard-crypto actions in the separate Ironwood bundle - they carry
/// the same per-action proving cost, so they count toward this limit exactly like Orchard V2
/// actions. Past NU6.3 the proposal represents these as the `Ironwood` pool (spends: a V3
/// `orchard::Note`; outputs/change: `PoolType` Ironwood), so the counts fold both pools together.
/// This is what the pre-`3e0b8039e` `Note::protocol()` (which reported every orchard-crypto note as
/// `Orchard`) did implicitly; here we spell it out since `Note::pool()` now splits V3 out as
/// `Ironwood`. In the default (pre-NU6.3, non-ironwood) build no Ironwood actions exist, so the
/// Ironwood arm contributes nothing and the count is unchanged.
fn step_orchard_actions<NoteRef>(
    step: &zcash_client_backend::proposal::Step<NoteRef>,
) -> (usize, usize) {
    let is_orchard_family =
        |pool: ShieldedPool| matches!(pool, ShieldedPool::Orchard | ShieldedPool::Ironwood);
    let is_orchard_family_pooltype =
        |pool: PoolType| matches!(pool, PoolType::Shielded(sp) if is_orchard_family(sp));

    let orchard_spends = step
        .shielded_inputs()
        .iter()
        .flat_map(|inputs| inputs.notes().iter())
        .filter(|note| is_orchard_family(note.note().pool()))
        .count();

    let orchard_outputs = step
        .payment_pools()
        .values()
        .filter(|&&pool| is_orchard_family_pooltype(pool))
        .count()
        + step
            .balance()
            .proposed_change()
            .iter()
            .filter(|change| is_orchard_family_pooltype(change.output_pool()))
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
fn classify_err(e: ProposalError) -> RpcError {
    use zcash_client_backend::data_api::error::Error;
    match &e {
        Error::InsufficientFunds {
            available,
            required,
        } => RpcError::insufficient_funds(format!(
            "Insufficient funds: {} zatoshis spendable, {} required (including fee)",
            u64::from(*available),
            u64::from(*required),
        ))
        .with_details(ErrorDetails::InsufficientFunds(InsufficientFunds {
            available: Some(u64::from(*available)),
            required: Some(u64::from(*required)),
            ..Default::default()
        })),
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
fn enrich_insufficient_funds(
    db: &WriteDb,
    engine_dir: &Path,
    policy: ConfirmationsPolicy,
    err: RpcError,
) -> RpcError {
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
    // Mature coinbase reads as spendable balance (`getbalance` counts it) but no regular send
    // can select it - without a hint, "wallet says X, send says 0 spendable" is a dead end the
    // caller can't diagnose. Same number as `getbalances.mine.coinbase` (both read
    // `mature_coinbase_zats`); best-effort - a failed lookup just leaves the hint off.
    let target_height = u32::from(summary.chain_tip_height()) + 1;
    let coinbase = super::read::mature_coinbase_zats(engine_dir, target_height).unwrap_or(0);
    if incoming == 0 && change == 0 && coinbase == 0 {
        return err;
    }
    // Carry forward whatever the selector already reported, so enriching the message never
    // costs a caller the shortfall numbers (`classify_err` attaches them; the message-sniffing
    // and change-strategy paths have none to attach).
    let (available, required) = match err.insufficient_funds_details() {
        Some(d) => (d.available, d.required),
        None => (None, None),
    };
    let mut msg = err.message;
    if incoming > 0 || change > 0 {
        msg = format!(
            "{msg}; awaiting confirmations: {incoming} zatoshis incoming, {change} zatoshis change \
 - these become spendable as blocks arrive"
        );
    }
    if coinbase > 0 {
        msg = format!("{msg}; {}", coinbase_hint(coinbase));
    }
    RpcError::insufficient_funds(msg).with_details(ErrorDetails::InsufficientFunds(
        InsufficientFunds {
            available,
            required,
            pending_incoming: incoming,
            pending_change: change,
            mature_coinbase: coinbase,
        },
    ))
}

/// The mature-coinbase `-6` hint, worded identically everywhere it appears (the proposal-path
/// enrichment above and the fully-transparent selection failures in `do_send_transparent`):
/// consensus lets a transparent coinbase output move only in a fully-shielded transaction, so
/// the one actionable next step is `z_shieldcoinbase`.
fn coinbase_hint(zats: u64) -> String {
    format!("{zats} zatoshis are mature coinbase, spendable only via z_shieldcoinbase")
}

#[cfg(test)]
mod tests {
    use super::gap_slots_remaining;
    use super::horizon_slots_remaining;
    use super::preexpose_progress_stats;
    use super::sanitize_upstream_msg;
    use super::select_transparent_inputs;
    use super::transparent_child_index;
    use super::DiversifierIndex;
    use super::ProvingKeys;

    /// The halt is keyed on the failure *type*, and only the terminal one. A transport failure or
    /// a wallet-apply failure must stay retryable: reconnecting fixes the first, and updating
    /// zecd fixes the second, so halting on either would strand a wallet that only needed to wait.
    #[test]
    fn only_an_unrecoverable_reorg_halts_sync() {
        use crate::sync::engine::{UnrecoverableReorg, WalletApplyError};
        use zcash_protocol::consensus::BlockHeight;

        let terminal: anyhow::Error = UnrecoverableReorg {
            at_height: BlockHeight::from_u32(3),
            requested: BlockHeight::from_u32(0),
            safe_rewind_height: Some(BlockHeight::from_u32(0)),
        }
        .into();
        assert!(super::sync_failure_is_terminal(&terminal));

        let apply: anyhow::Error = WalletApplyError("commitment tree conflict".into()).into();
        assert!(
            !super::sync_failure_is_terminal(&apply),
            "an apply-side failure can clear on its own (e.g. after a zecd update)"
        );
        assert!(
            !super::sync_failure_is_terminal(&anyhow::anyhow!("connection reset")),
            "a transport failure is fixed by reconnecting"
        );
    }

    /// Every `get` shares one [`super::ProvingKeyCache`] rather than generating a key per send.
    /// The regtest tier cannot catch a regression here - rebuilding per send is slower, not
    /// wrong, and e2e send timings are noise-dominated.
    ///
    /// `#[ignore]` because a *debug* keygen is ~25 s (measured on 4 cores) - too slow for the
    /// offline tier, whose value is being fast and always green. Run it with
    /// `cargo test -- --include-ignored`, and after any `orchard`/`halo2_proofs` bump.
    #[ignore = "runs a real Orchard keygen: ~25s in a debug build"]
    #[tokio::test]
    async fn proving_keys_are_built_once_and_shared() {
        // `false`: skip the Ironwood keygen, which this assertion doesn't need.
        let keys = ProvingKeys::new(false);
        let first = keys.get().await.expect("keygen");
        let second = keys.get().await.expect("keygen");
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "each call rebuilt the proving key instead of sharing the cached one"
        );
    }

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
    fn tia_check_range_extends_to_tip_and_skips_unmined() {
        use super::tia_check_range;
        // The windowed request (start + ~40 blocks) is extended straight to the tip: one query
        // instead of thousands of sequential windows on a deep restore.
        assert_eq!(
            tia_check_range(4_080_346, 4_215_261),
            Some((4_080_346, 4_215_261))
        );
        // Start at the tip: a single-block check.
        assert_eq!(
            tia_check_range(4_215_261, 4_215_261),
            Some((4_215_261, 4_215_261))
        );
        // Genesis is unservable (zebra can't parse block 0); the start clamps to 1.
        assert_eq!(tia_check_range(0, 100), Some((1, 100)));
        // Start beyond the tip (spend-search for a still-unmined funding tx): nothing checkable,
        // and the caller must not notify - the old code notified anyway and tripped the backend's
        // `as_of == block_range_end - 1` check, aborting the enhancement pass every time.
        assert_eq!(tia_check_range(101, 100), None);
    }

    #[test]
    fn a_server_without_transparent_block_data_is_refused_only_when_it_matters() {
        use super::transparent_capability_error;
        // The default wallet is shielded-only and works against any server, old or new.
        assert!(transparent_capability_error(false, false).is_none());
        assert!(transparent_capability_error(false, true).is_none());
        // So does a transparent wallet on a backend whose block scan carries transparent data
        // (zebra, or lightwalletd 0.5.0+).
        assert!(transparent_capability_error(true, true).is_none());
        // The one refused combination. The message has to name the fix, because the failure it
        // replaces - transparent receives silently never appearing - gives no other clue. The
        // most likely fix is the override: no released lightwalletd advertises the capability,
        // so a server that *does* serve the data still lands here.
        let why = transparent_capability_error(true, false).expect("must be refused");
        assert!(
            why.contains("assume_transparent_in_compact_blocks"),
            "should name the override knob: {why}"
        );
        assert!(why.contains("transparent"), "{why}");
    }

    #[test]
    fn scan_progress_ratio_tracks_height_not_note_weight() {
        use super::scan_progress_ratio;
        // Mid-restore: 50 of 100 blocks past the birthday scanned = 0.5 (the note-weighted
        // upstream ratio would already read 1.0 here - the bug this helper replaces).
        let mid = scan_progress_ratio(1_000, 1_050, 1_100);
        assert!((mid - 0.5).abs() < 1e-9, "mid {mid}");
        // Scan start and completion.
        assert_eq!(scan_progress_ratio(1_000, 1_000, 1_100), 0.0);
        assert_eq!(scan_progress_ratio(1_000, 1_100, 1_100), 1.0);
        // Fresh wallet (tip at/below the birthday): nothing to scan is complete, not 0/0.
        assert_eq!(scan_progress_ratio(1_000, 1_000, 1_000), 1.0);
        assert_eq!(scan_progress_ratio(1_000, 999, 999), 1.0);
        // Clamped: a scanned height past the tip (transient) or below the birthday never leaves
        // [0, 1].
        assert_eq!(scan_progress_ratio(1_000, 1_200, 1_100), 1.0);
        assert_eq!(scan_progress_ratio(1_000, 900, 1_100), 0.0);
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

    #[test]
    fn horizon_slots_remaining_counts_down_and_saturates() {
        // The exchange shape: initial_scan 70_000 + gap 1_000 -> horizon 71_000. Issuing
        // the first floor index (70_000) leaves 999 recoverable slots - no warning noise on
        // every address, the misconfiguration bait behind the 0.5.1-rc2 field report.
        assert_eq!(horizon_slots_remaining(71_000, 70_000), 999);
        // The last in-horizon index leaves nothing.
        assert_eq!(horizon_slots_remaining(71_000, 70_999), 0);
        // At or past the horizon: saturates to 0 (the beyond-horizon warn/fail-closed case).
        assert_eq!(horizon_slots_remaining(71_000, 71_000), 0);
        assert_eq!(horizon_slots_remaining(71_000, 80_000), 0);
        // No floor configured: the horizon is just the gap limit, anchored at index 0.
        assert_eq!(horizon_slots_remaining(20, 0), 19);
        assert_eq!(horizon_slots_remaining(20, 19), 0);
        // Overflow-safe at the top of the index space.
        assert_eq!(horizon_slots_remaining(u32::MAX, u32::MAX), 0);
    }

    /// The enhancement watermark stops one below the lowest pending request, never above the
    /// scanned frontier, and covers the whole scanned range when the backlog is empty.
    ///
    /// The load-bearing case is the middle one: a consumer replaying memos as a log advances a
    /// cursor over what it reads, and an output whose memo has not been backfilled yet is
    /// invisible to a `memo IS NOT NULL` filter. If the watermark ever reached the height of a
    /// still-pending request, that output would be behind the cursor by the time enhancement
    /// filled it in - skipped permanently, with nothing to detect it.
    #[test]
    fn enhancement_watermark_stops_below_the_lowest_pending_request() {
        use super::enhanced_through;
        // Empty backlog: the whole scanned range is enhanced.
        assert_eq!(enhanced_through(240, None), 240);
        // A pending request at height 100 leaves 0..=99 enhanced.
        assert_eq!(enhanced_through(240, Some(100)), 99);
        // The scanned frontier still caps it: nothing above it has been scanned at all.
        assert_eq!(enhanced_through(50, Some(100)), 50);
        assert_eq!(enhanced_through(50, None), 50);
        // A request against the genesis-adjacent floor cannot underflow, and reports that
        // nothing is known to be enhanced.
        assert_eq!(enhanced_through(240, Some(0)), 0);
        assert_eq!(enhanced_through(0, Some(0)), 0);
        // The boundary: a request at height h never leaves h itself claimed as enhanced.
        for h in [1u32, 2, 1_000, 3_428_143] {
            assert!(
                enhanced_through(u32::MAX, Some(h)) < h,
                "watermark must stay strictly below a pending request at {h}"
            );
        }
    }

    /// The recovery horizon is anchored at the restore floor - the larger of the configured
    /// `transparent_initial_scan` and the account default address's frontier - not at zero.
    /// Account creation exposes the default Unified Address's transparent receiver at the seed's
    /// first all-receivers-valid diversifier index, and every restore of the seed re-derives the
    /// same exposure, so restore coverage genuinely starts there. Without the anchor, a seed
    /// whose default address lands at an index >= gap_limit reported a *fresh restore* as beyond
    /// its own horizon (`restorable: false`) - the intermittent `regtest_transparent_gap` CI
    /// failure (frontiers 5/6/10 with gap 3, one per fresh per-run mnemonic).
    #[test]
    fn recovery_horizon_is_anchored_at_the_restore_floor() {
        use super::recovery_horizon_for;
        // No anchor known (no account yet / no transparent component): the configured floor.
        assert_eq!(recovery_horizon_for(0, None, 3), 3);
        assert_eq!(recovery_horizon_for(70_000, None, 1_000), 71_000);
        // The common case (default address at index 0 -> frontier 1): a fresh wallet's day-one
        // coverage is 0..=gap_limit (row 0 plus the lookahead 1..=gap), so the horizon is
        // gap_limit + 1 - exact where the un-anchored formula understated by one.
        assert_eq!(recovery_horizon_for(0, Some(1), 3), 4);
        // A seed whose default address lands past the gap: the horizon follows it, because a
        // restore's matcher starts its lookahead there (frontier 6 -> coverage through 8).
        assert_eq!(recovery_horizon_for(0, Some(6), 3), 9);
        // A deep initial_scan floor dominates a small default-address frontier (A18 shape).
        assert_eq!(recovery_horizon_for(25, Some(1), 3), 28);
        // Overflow-safe.
        assert_eq!(recovery_horizon_for(u32::MAX, Some(1), 3), u32::MAX);
    }

    /// `z_getaddressforaccount 0 ["p2pkh"] <index>` reuses the diversifier-index argument for a
    /// BIP 44 child index, so the hardened half (and anything above the 32-bit range the shielded
    /// diversifier space allows) has to be rejected rather than silently truncated.
    #[test]
    fn transparent_child_index_accepts_only_the_non_hardened_range() {
        for i in [0u32, 1, 20, 70_000, (1u32 << 31) - 1] {
            assert_eq!(
                transparent_child_index(DiversifierIndex::from(i)),
                Some(i),
                "index {i} is a valid transparent child index"
            );
        }
        // The hardened bit, and values beyond u32 (the diversifier space runs to ~2^88).
        for j in [
            DiversifierIndex::from(1u32 << 31),
            DiversifierIndex::from(u32::MAX),
            DiversifierIndex::from(u64::from(u32::MAX) + 1),
        ] {
            assert_eq!(transparent_child_index(j), None, "{:?}", u128::from(j));
        }
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
        // Inputs cover recipient + the no-change fee exactly -> no change output.
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
        // 2-in/2-out -> max(2,2)=2 actions.
        assert_eq!(fee, MARGINAL * 2);
        assert_eq!(change, 120_000_000 - 100_000_000 - fee);
        assert_eq!(120_000_000, 100_000_000 + change + fee);
    }

    #[test]
    fn transparent_selection_fee_scales_with_input_count() {
        // Three inputs, one recipient + change -> 3-in/2-out -> max(3,2)=3 actions.
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
        // One large input, two recipients + change -> 1-in/3-out -> max(grace, max(1,3)) = 3 actions.
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
        // 17 P2SH recipient outputs (32 bytes each) total 544 bytes -> ceil(544/34) = 16 output
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
        // With change: total out = 544 + 34 = 578 -> ceil(578/34) = 17 actions; 1 input -> fee = 17m.
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

        // Two bare transparent recipients -> Some, with amounts preserved in order.
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

    /// The t→t merge fee is the transaction `Builder`'s own ZIP-317 arithmetic for n P2PKH
    /// inputs and exactly one output, no change - a mismatch makes the builder reject the
    /// transaction at execute, so this math is load-bearing, not advisory.
    #[test]
    fn merge_transparent_fee_matches_builder_arithmetic() {
        use super::merge_transparent_fee;
        // One input, one P2PKH output (34 bytes → 1 output action): the grace floor of 2
        // actions applies.
        assert_eq!(
            merge_transparent_fee(1, P2PKH_OUT, P2PKH_OUT, MARGINAL, GRACE),
            MARGINAL * 2
        );
        // 50 inputs dominate the single output: 50 actions.
        assert_eq!(
            merge_transparent_fee(50, P2PKH_OUT, P2PKH_OUT, MARGINAL, GRACE),
            MARGINAL * 50
        );
        // A P2SH output (32 bytes) still prices as one output action.
        assert_eq!(
            merge_transparent_fee(3, 8 + 1 + 23, P2PKH_OUT, MARGINAL, GRACE),
            MARGINAL * 3
        );
    }

    /// The merge's destination-pool resolution mirrors librustzcash's
    /// `resolve_shielded_destination`: Orchard receivers take precedence and land in Ironwood
    /// once NU6.3 is active (else Orchard); Sapling-only recipients land in Sapling. Getting
    /// this wrong desynchronizes the hand-computed fee from the transaction the builder makes.
    #[test]
    fn merge_shielded_destination_pool_resolves_by_receiver_and_activation() {
        use super::merge_shielded_destination_pool;
        use crate::network::ZNetwork;
        use zcash_keys::address::{Address, UnifiedAddress};
        use zcash_keys::keys::{ReceiverRequirement::*, UnifiedAddressRequest, UnifiedSpendingKey};
        use zcash_protocol::PoolType;
        use zip32::{AccountId, DiversifierIndex};

        let net = ZNetwork::Test;
        let ufvk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        let (ua, _) = ufvk
            .find_address(
                DiversifierIndex::new(),
                UnifiedAddressRequest::unsafe_custom(Require, Require, Omit),
            )
            .unwrap();
        let orchard_dest = Address::Unified(
            UnifiedAddress::from_receivers(ua.orchard().cloned(), None, None).unwrap(),
        );
        let sapling_dest = Address::Sapling(ua.sapling().cloned().unwrap());

        assert_eq!(
            merge_shielded_destination_pool(&orchard_dest, true).unwrap(),
            PoolType::IRONWOOD
        );
        assert_eq!(
            merge_shielded_destination_pool(&orchard_dest, false).unwrap(),
            PoolType::ORCHARD
        );
        // Sapling-only stays Sapling regardless of activation.
        assert_eq!(
            merge_shielded_destination_pool(&sapling_dest, true).unwrap(),
            PoolType::SAPLING
        );
        // A dual UA resolves to the Orchard-family side (delivery precedence).
        assert_eq!(
            merge_shielded_destination_pool(&Address::Unified(ua), true).unwrap(),
            PoolType::IRONWOOD
        );
    }

    /// A transparent source plus *any* transparent recipient is a fully transparent transaction
    /// (needs `AllowFullyTransparent`), including the mixed case that falls past
    /// `transparent_only_recipients` onto the proposal path - the gate this predicate backs.
    #[test]
    fn request_pays_transparent_output_flags_any_bare_transparent_recipient() {
        use super::request_pays_transparent_output;
        use crate::network::ZNetwork;
        use zcash_keys::address::Address;
        use zcash_keys::keys::{ReceiverRequirement::*, UnifiedAddressRequest, UnifiedSpendingKey};
        use zcash_protocol::value::Zatoshis;
        use zcash_transparent::address::TransparentAddress;
        use zip32::{AccountId, DiversifierIndex};
        use zip321::{Payment, TransactionRequest};

        let net = ZNetwork::Test;
        let taddr =
            Address::Transparent(TransparentAddress::PublicKeyHash([9; 20])).to_zcash_address(&net);
        let shielded = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key()
            .find_address(
                DiversifierIndex::new(),
                UnifiedAddressRequest::unsafe_custom(Require, Require, Omit),
            )
            .unwrap()
            .0;
        let shielded = Address::Unified(shielded).to_zcash_address(&net);
        let pay = |a: &zcash_address::ZcashAddress| {
            Payment::without_memo(a.clone(), Zatoshis::const_from_u64(10_000_000))
        };

        // All-shielded → no transparent output.
        let req = TransactionRequest::new(vec![pay(&shielded)]).unwrap();
        assert!(!request_pays_transparent_output(&net, &req));
        // Mixed (shielded + bare transparent) → flagged, unlike `transparent_only_recipients`.
        let req = TransactionRequest::new(vec![pay(&shielded), pay(&taddr)]).unwrap();
        assert!(request_pays_transparent_output(&net, &req));
        // All-transparent → flagged too (normally caught earlier by the t->t branch).
        let req = TransactionRequest::new(vec![pay(&taddr)]).unwrap();
        assert!(request_pays_transparent_output(&net, &req));
    }

    /// `spend_policy_for_source` is the one-source-per-send invariant: a transparent source
    /// permits no shielded pools (a shortfall is `-6`, never a top-up from notes) and excludes
    /// coinbase (which stays `z_shieldcoinbase`'s alone); a shielded/unspecified source keeps
    /// the default fully-shielded selection with no transparent spending.
    #[test]
    fn spend_policy_for_source_maps_sources_to_selection_policies() {
        use super::spend_policy_for_source;
        use crate::wallet::SendSource;
        use zcash_client_backend::data_api::wallet::input_selection::{
            CoinbasePolicy, TransparentSource,
        };
        use zcash_transparent::address::TransparentAddress;

        let default = spend_policy_for_source(SendSource::Unspecified);
        assert!(default.transparent().is_none());
        assert!(!default.shielded().is_empty());
        let shielded = spend_policy_for_source(SendSource::Shielded);
        assert!(shielded.transparent().is_none());
        assert!(!shielded.shielded().is_empty());

        let any = spend_policy_for_source(SendSource::Transparent(None));
        assert!(any.shielded().is_empty(), "one source per send");
        let tsp = any.transparent().expect("transparent spending enabled");
        assert!(matches!(tsp.source(), TransparentSource::AnyAccountAddr));
        assert_eq!(tsp.coinbase(), CoinbasePolicy::NonCoinbase);

        let addr = TransparentAddress::PublicKeyHash([3; 20]);
        let one = spend_policy_for_source(SendSource::Transparent(Some(addr)));
        assert!(one.shielded().is_empty(), "one source per send");
        let tsp = one.transparent().expect("transparent spending enabled");
        assert!(matches!(tsp.source(), TransparentSource::FromAddresses(_)));
        assert_eq!(tsp.coinbase(), CoinbasePolicy::NonCoinbase);
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

    /// A post-connection failure (tip refresh against a reachable-but-degraded upstream, a sync
    /// error, a stale-client op) routes through `mark_disconnected`, which paces the next
    /// reconnect via `reconnect_after_backoff`. The deadline must land in the future (never in the
    /// past, which is what let the idle loop tight-loop and peg a core), and the backoff must
    /// advance across repeated failures so a persistently degraded upstream is retried ever more
    /// gently rather than pinned at the base delay.
    #[test]
    fn post_connection_failures_pace_and_grow_the_reconnect_deadline() {
        use super::reconnect_after_backoff;
        use crate::backoff::Backoff;
        use std::time::{Duration, Instant};

        let mut backoff = Backoff::new(Duration::from_secs(30), Duration::from_secs(300));
        let now = Instant::now();

        // Every disconnect schedules a reconnect at or after `now` - never behind it - so the
        // idle wait (`reconnect_at.saturating_duration_since(now)`) can't collapse to an
        // immediate retry loop the way an unset `reconnect_at` did.
        for _ in 0..8 {
            let deadline = reconnect_after_backoff(now, &mut backoff);
            assert!(
                deadline >= now,
                "reconnect deadline must not be in the past"
            );
        }

        // The attempt counter advanced with each failure, so the (pre-jitter) cap has grown past
        // the base delay: the pacing actually escalates rather than sitting at the base.
        assert!(
            backoff.cap() > Duration::from_secs(30),
            "backoff cap should grow across repeated post-connection failures, got {:?}",
            backoff.cap()
        );
    }

    /// The sync-error arm floors its backoff-paced deadline at `SYNC_ERROR_RETRY_INTERVAL`
    /// (`reconnect_at.max(sync_error_retry_deadline(now))`), so even a near-zero jitter draw
    /// (full-jitter backoff can return ~0) still caps a persistent sync error to one attempt per
    /// interval instead of spinning. Guards the `.max` composition specifically (the helper
    /// itself is covered by `sync_error_paces_the_next_reconnect`).
    #[test]
    fn sync_error_reconnect_respects_the_retry_floor() {
        use super::{sync_error_retry_deadline, SYNC_ERROR_RETRY_INTERVAL};
        use std::time::Instant;

        let now = Instant::now();
        // Simulate `mark_disconnected` having drawn a zero-length jitter (deadline == now); the
        // floor must win.
        let backoff_paced = now;
        let floored = backoff_paced.max(sync_error_retry_deadline(now));
        assert_eq!(floored, now + SYNC_ERROR_RETRY_INTERVAL);
    }

    /// After a sync error the actor must push its next reconnect a real interval into the
    /// future, not retry immediately. A persistent sync error (e.g. an unrecoverable reorg
    /// whose rewind target has no checkpoint) otherwise spins: dropping the client makes the
    /// idle loop reconnect at once, the reconnect succeeds (so the connect backoff never
    /// engages), and the next batch re-hits the same error hundreds of times a second. This
    /// guards the pacing the run loop's sync-error arm applies via `sync_error_retry_deadline`.
    #[test]
    fn sync_error_paces_the_next_reconnect() {
        use super::{sync_error_retry_deadline, SYNC_ERROR_RETRY_INTERVAL};
        use std::time::{Duration, Instant};

        let now = Instant::now();
        let deadline = sync_error_retry_deadline(now);

        // The retry is scheduled exactly one interval out...
        assert_eq!(
            deadline.saturating_duration_since(now),
            SYNC_ERROR_RETRY_INTERVAL
        );
        // ...and that interval is a meaningful floor, not ~0 (which would re-introduce the spin).
        assert!(
            SYNC_ERROR_RETRY_INTERVAL >= Duration::from_secs(1),
            "the sync-error pace must be a real floor to prevent a busy loop"
        );
        // The deadline is strictly in the future of the error, so the idle loop waits.
        assert!(deadline > now);
    }

    /// The sync-failure diagnostics ladder (`sync_failure_hint`): transport failures are never
    /// attributed (reconnecting genuinely fixes those, and telling an operator to rebuild a
    /// wallet over a zebra outage would be harmful); an apply-side failure under an active
    /// unsupported network upgrade is attributed immediately (the "old zecd after activation"
    /// loop); and an apply-side failure that keeps repeating with no upgrade in play points at
    /// the `zecd rescan` database rebuild - each with the operator action (update / rescan /
    /// forum report) spelled out in the message.
    #[test]
    fn sync_failure_hint_attributes_only_diagnosable_failures() {
        use super::{sync_failure_hint, PERSISTENT_SYNC_ERROR_THRESHOLD};
        use crate::chain::UnsupportedUpgrade;

        let upgrade = UnsupportedUpgrade {
            branch_id: 0xdead_beef,
            name: "NU-Future".to_string(),
            activation_height: Some(4_100_000),
            active: true,
        };

        // Transport-class failures: no hint, no matter the streak or upgrade state.
        assert_eq!(sync_failure_hint(false, 100, "default", None), None);
        assert_eq!(
            sync_failure_hint(false, 100, "default", Some(&upgrade)),
            None
        );

        // Apply-side + unsupported upgrade: attributed on the very first failure, naming the
        // upgrade, its branch ID and height, and the update-or-report action.
        let hint = sync_failure_hint(true, 1, "default", Some(&upgrade))
            .expect("an active unsupported upgrade explains the failure immediately");
        assert!(hint.contains("NU-Future"), "{hint}");
        assert!(hint.contains("0xdeadbeef"), "{hint}");
        assert!(hint.contains("4100000"), "{hint}");
        assert!(hint.contains("latest zecd release"), "{hint}");
        assert!(hint.contains("forum.zcashcommunity.com"), "{hint}");

        // Apply-side, no upgrade: quiet below the persistence threshold (a one-off apply error
        // can be a reorg racing the batch)...
        assert_eq!(
            sync_failure_hint(true, PERSISTENT_SYNC_ERROR_THRESHOLD - 1, "default", None),
            None
        );
        // ...and at the threshold, the wallet database is the prime suspect: point at the
        // keys-preserving `zecd rescan` rebuild (naming the wallet) and the forum.
        let hint = sync_failure_hint(true, PERSISTENT_SYNC_ERROR_THRESHOLD, "burner", None)
            .expect("a persistent apply failure escalates to recovery guidance");
        assert!(hint.contains("zecd rescan --wallet burner"), "{hint}");
        assert!(hint.contains("keys.toml is kept"), "{hint}");
        assert!(hint.contains("forum.zcashcommunity.com"), "{hint}");

        // An upstream-supplied upgrade name is operator-trusted, not wire-trusted: control
        // characters are stripped before it is echoed into the log line.
        let hostile = UnsupportedUpgrade {
            name: "NU\x1b[2J\x07-Evil".to_string(),
            ..upgrade
        };
        let hint = sync_failure_hint(true, 1, "default", Some(&hostile)).expect("still hints");
        assert!(hint.contains("NU[2J-Evil"), "{hint}");
        assert!(!hint.contains('\x1b'), "control chars stripped: {hint:?}");
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

    /// The cached-Orchard PCZT extractor is handed no Sapling verifying key, so a send that pays a
    /// Sapling output must be diverted to the fused path. `request_pays_sapling_output`
    /// is that routing predicate: it flags a bare Sapling recipient (a Sapling-only UA too), but not
    /// an Orchard recipient or a dual Orchard+Sapling UA - an Orchard-only wallet pays such a UA on
    /// its Orchard receiver, producing no Sapling output. Without the divert,
    /// `extract_and_store_transaction_from_pczt` rejects the PCZT and the send fails after proving.
    #[test]
    fn request_pays_sapling_output_flags_only_sapling_only_recipients() {
        use super::request_pays_sapling_output;
        use crate::network::ZNetwork;
        use zcash_address::ZcashAddress;
        use zcash_keys::address::{Address, UnifiedAddress};
        use zcash_keys::keys::{ReceiverRequirement::*, UnifiedAddressRequest, UnifiedSpendingKey};
        use zcash_protocol::value::Zatoshis;
        use zip32::{AccountId, DiversifierIndex};
        use zip321::{Payment, TransactionRequest};

        let net = ZNetwork::Test;
        // A UA carrying both shielded receivers (Sapling + Orchard), no transparent.
        let both = UnifiedAddressRequest::unsafe_custom(Require, Require, Omit);
        let ufvk = UnifiedSpendingKey::from_seed(&net, &[7u8; 32], AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        let (ua, _) = ufvk.find_address(DiversifierIndex::new(), both).unwrap();

        // Three recipient shapes built from that one address's receivers.
        let sapling_only = Address::Sapling(ua.sapling().cloned().unwrap());
        let orchard_only = Address::Unified(
            UnifiedAddress::from_receivers(ua.orchard().cloned(), None, None).unwrap(),
        );
        let dual = Address::Unified(ua.clone());

        // A one-payment request paying `addr` 1 ZEC.
        let request_to = |addr: &Address| {
            let zaddr = ZcashAddress::try_from_encoded(&addr.encode(&net)).unwrap();
            let payment = Payment::without_memo(zaddr, Zatoshis::const_from_u64(100_000_000));
            TransactionRequest::new(vec![payment]).unwrap()
        };

        assert!(
            request_pays_sapling_output(&net, &request_to(&sapling_only)),
            "a bare Sapling recipient forces a Sapling output → must divert to the fused path"
        );
        assert!(
            !request_pays_sapling_output(&net, &request_to(&orchard_only)),
            "an Orchard recipient stays on the cached PCZT path"
        );
        assert!(
            !request_pays_sapling_output(&net, &request_to(&dual)),
            "a dual Orchard+Sapling UA is paid on its Orchard receiver → no Sapling output"
        );

        // A multi-recipient send diverts if *any* payment forces a Sapling output.
        let mixed = TransactionRequest::new(vec![
            Payment::without_memo(
                ZcashAddress::try_from_encoded(&orchard_only.encode(&net)).unwrap(),
                Zatoshis::const_from_u64(1),
            ),
            Payment::without_memo(
                ZcashAddress::try_from_encoded(&sapling_only.encode(&net)).unwrap(),
                Zatoshis::const_from_u64(1),
            ),
        ])
        .unwrap();
        assert!(
            request_pays_sapling_output(&net, &mixed),
            "one Sapling recipient among several diverts the whole send"
        );
    }

    /// The enhancement backlog counts the requests zecd can actually service, which is all three
    /// variants: `Enhancement`/`GetStatus` via a full-tx fetch, and the transparent-address
    /// variant via the address-index query. A variant zecd could not drain would have to be
    /// excluded, or it would pin `pending_enhancements` above zero forever and a wallet would
    /// never report ready.
    #[test]
    fn serviceable_request_classification() {
        use super::is_serviceable_request;
        use zcash_client_backend::data_api::{
            OutputStatusFilter, TransactionDataRequest, TransactionStatusFilter,
        };
        use zcash_protocol::consensus::BlockHeight;
        use zcash_protocol::TxId;
        use zcash_transparent::address::TransparentAddress;

        let txid = TxId::from_bytes([7u8; 32]);
        assert!(is_serviceable_request(
            &TransactionDataRequest::Enhancement(txid)
        ));
        assert!(is_serviceable_request(&TransactionDataRequest::GetStatus(
            txid
        )));
        assert!(
            is_serviceable_request(&TransactionDataRequest::transactions_involving_address(
                TransparentAddress::PublicKeyHash([9u8; 20]),
                BlockHeight::from_u32(1),
                Some(BlockHeight::from_u32(100)),
                None,
                TransactionStatusFilter::All,
                OutputStatusFilter::All,
            )),
            "the transparent address-index query drains, so it counts toward the backlog"
        );
    }

    /// FullPrivacy's single-pool rule: violated by any transparent component, or by touching more
    /// than one shielded pool (a turnstile crossing). A transaction confined to one shielded pool
    /// is fine.
    #[test]
    fn single_pool_rule() {
        use super::single_pool_violated;
        // Single shielded pool - allowed.
        assert!(!single_pool_violated(false, true, false, false)); // Sapling only
        assert!(!single_pool_violated(false, false, true, false)); // Orchard only
        assert!(!single_pool_violated(false, false, false, true)); // Ironwood only
                                                                   // Cross-pool turnstile - rejected.
        assert!(single_pool_violated(false, true, true, false));
        // Any transparent component - rejected.
        assert!(single_pool_violated(true, false, true, false));
        assert!(single_pool_violated(true, true, false, false));
        assert!(single_pool_violated(true, false, false, false));
    }

    /// Ironwood is its own pool for FullPrivacy, not a flavour of Orchard. Post-NU6.3 a wallet's
    /// shielded funds are ironwood notes, so paying a Sapling recipient from them moves value
    /// between two distinct pools and reveals the amount via `valueBalance` - exactly the leak the
    /// policy exists to forbid. Before this was fixed the check consulted only Sapling and Orchard,
    /// so an ironwood->Sapling send scored `sapling && !orchard` and FullPrivacy passed it.
    ///
    /// NB the upstream *input-selection* grouping puts {Sapling, Ironwood} together; that is about
    /// which notes may fund one transaction and must not be reused as a privacy equivalence.
    #[test]
    fn ironwood_crossings_violate_full_privacy() {
        use super::single_pool_violated;
        // The regression: ironwood funding a Sapling output is a turnstile crossing.
        assert!(
            single_pool_violated(false, true, false, true),
            "ironwood<->Sapling reveals the crossed amount and must be rejected"
        );
        // The same holds against Orchard, and for a step touching all three.
        assert!(single_pool_violated(false, false, true, true));
        assert!(single_pool_violated(false, true, true, true));
        // A transparent component is still rejected alongside ironwood.
        assert!(single_pool_violated(true, false, false, true));
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
        // Only outputs overflow -> blame outputs.
        assert_eq!(orchard_action_overflow(3, 51, 50), Some((51, "outputs")));
        // Only inputs overflow -> blame inputs.
        assert_eq!(orchard_action_overflow(80, 2, 50), Some((80, "inputs")));
        // Both overflow -> blame actions (the max).
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
            super::enrich_insufficient_funds(&db, dir.path(), Default::default(), other.clone())
                .message,
            other.message
        );

        let bare = RpcError::insufficient_funds("Insufficient funds: 0 zatoshis spendable");
        let out =
            super::enrich_insufficient_funds(&db, dir.path(), Default::default(), bare.clone());
        assert_eq!(out.code, codes::RPC_WALLET_INSUFFICIENT_FUNDS);
        assert_eq!(
            out.message, bare.message,
            "no pending balance and no mature coinbase, so no enrichment"
        );
    }

    /// Enrichment rebuilds the error to append its hints, so the shortfall numbers the selector
    /// reported have to be carried across that rebuild - a caller that reads `required` from the
    /// details must not lose it just because the wallet also had pending value to mention.
    #[test]
    fn enrichment_preserves_the_selector_reported_amounts() {
        use crate::error::{ErrorDetails, InsufficientFunds, RpcError};

        let with_amounts = RpcError::insufficient_funds("Insufficient funds").with_details(
            ErrorDetails::InsufficientFunds(InsufficientFunds {
                available: Some(10),
                required: Some(25),
                ..Default::default()
            }),
        );
        let carried = match with_amounts.insufficient_funds_details() {
            Some(d) => (d.available, d.required),
            None => panic!("details were attached"),
        };
        assert_eq!(carried, (Some(10), Some(25)));
    }

    /// The mature-coinbase hint must name the value and the one actionable next step - the
    /// regtest coinbase e2e asserts the live `-6` carries this exact marker.
    #[test]
    fn coinbase_hint_names_z_shieldcoinbase() {
        let hint = super::coinbase_hint(1_250);
        assert!(hint.contains("1250 zatoshis"), "{hint}");
        assert!(hint.contains("z_shieldcoinbase"), "{hint}");
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
