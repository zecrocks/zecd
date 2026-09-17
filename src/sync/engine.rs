//! The block-sync loop, ported from `zcash-devtool/src/commands/wallet/sync.rs` and
//! refactored to (a) process one batch per call so the owning actor can interleave RPC
//! commands between batches, and (b) run against any [`ChainSource`] backend (lightwalletd
//! gRPC or direct zebrad JSON-RPC) rather than the lightwalletd client concretely. TUI and
//! transparent-input handling are removed (Orchard-only).
//!
//! # Reorg handling: why it lives here and not in librustzcash
//!
//! Reorg *detection* is librustzcash's job: `scan_cached_blocks` checks `prev_hash`
//! continuity and returns a `ChainError::Scan` with `is_continuity_error() == true` when the
//! served chain contradicts stored history. Only the *recovery* lives here, and that is by
//! upstream design, not accident: the `zcash_client_backend::data_api::chain` module docs
//! prescribe exactly this caller-side protocol - catch the continuity error, pick a rewind
//! height (`at_height - 10` is upstream's own example heuristic), `truncate_to_height`, drop
//! the cached blocks - because rewind depth and cache management are application policy.
//!
//! librustzcash does ship a turnkey driver (`zcash_client_backend::sync::run`, behind the
//! `sync` feature) whose reorg branch matches `scan_blocks` below, but it is unusable here
//! for two reasons: it is a blocking run-until-caught-up loop (this actor needs one batch
//! per call so RPC commands interleave), and it propagates `RequestedRewindInvalid`
//! unhandled - a young wallet hit by a reorg near its birthday would re-fail the same scan
//! range forever. `perform_rewind`'s shallow retry exists to close that second gap; see
//! its docs. Do not "simplify" this module down to what `sync::run` does: that version
//! wedges.

use std::collections::{HashMap, HashSet};
use std::future::Future;

use orchard::tree::MerkleHashOrchard;
use prost::Message;
use tracing::{info, warn};
use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
use zcash_client_backend::data_api::{
    chain::{error::Error as ChainError, scan_cached_blocks, ChainState, CommitmentTreeRoot},
    scanning::{ScanPriority, ScanRange},
    WalletCommitmentTrees, WalletRead, WalletWrite,
};
use zcash_client_backend::wallet::WalletTransparentOutput;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::AccountUuid;
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedPool, TxId};
use zcash_transparent::address::TransparentAddress;
use zip32::DiversifierIndex;

use crate::chain::ChainSource;
use crate::network::ZNetwork;
use crate::sync::memcache::MemBlockCache;
use crate::wallet::open::WriteDb;

/// The default blocks per download-and-scan batch, and the value `[sync] batch_size`
/// overrides. Kept as a named constant because [`REORG_MAX_MARGIN`] is defined in terms of it:
/// a rewind never usefully goes further back than one batch would re-scan.
pub const DEFAULT_BATCH_SIZE: u32 = 10_000;

/// How often (at most) to log progress while recording a batch's matched transparent receives.
/// Normally the whole loop is milliseconds and never logs; each recorded receive re-derives the
/// wallet's transparent gap window, so under a wide `transparent_gap_limit` a single batch can
/// legitimately take minutes and this heartbeat is what distinguishes it from a hang.
const TRANSPARENT_RECORD_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// A wallet-side failure applying an already-downloaded batch (the scan/commit stage of
/// [`sync_one_batch`]): the upstream served the range fine, but scanning it into the local
/// wallet database failed - e.g. `Wallet(PutBlocksCommitmentTree { .. Insert(Conflict(..)) })`
/// from an inconsistent on-disk note-commitment tree, or blocks past a network upgrade this
/// build cannot parse. Wrapped as a distinct type (recoverable via `anyhow`'s `downcast_ref`)
/// so the actor can tell this class apart from transport failures: reconnecting can fix a
/// transport error, but a *persistent* apply failure at the same range means the local
/// database cannot accept valid chain data, and the actor escalates its log guidance
/// accordingly (unsupported upgrade → update zecd; otherwise → `zecd rescan`).
#[derive(Debug)]
pub struct WalletApplyError(pub String);

impl std::fmt::Display for WalletApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WalletApplyError {}

/// A reorg the wallet cannot rewind past: every truncation target at or below the conflict was
/// refused, so the conflicting block cannot be removed and no retry will ever apply the range.
/// Only an operator-driven `zecd rescan` clears it.
///
/// Typed (recoverable via `anyhow`'s `downcast_ref`) because it is the one sync failure that is
/// **terminal**: every other class - transport, a transient apply error - is worth retrying, and
/// the actor's loop is built around retrying. Without this distinction a wedged wallet retries
/// the identical failure forever (measured: 280 identical attempts over ten minutes, each
/// dropping and re-establishing the upstream connection), which reads in the log like a flaky
/// upstream rather than a wallet that needs rebuilding. See [`super::super::wallet::actor`]'s
/// halt handling.
#[derive(Debug)]
pub struct UnrecoverableReorg {
    /// Height of the block whose continuity check failed.
    pub at_height: BlockHeight,
    /// The rewind target the caller asked for (the reorg margin below `at_height`).
    pub requested: BlockHeight,
    /// The lowest height the storage layer said it could rewind to, if it named one. It is
    /// reported even when it is the very height that was just refused, so it is guidance for a
    /// human, not a target to retry blindly.
    pub safe_rewind_height: Option<BlockHeight>,
}

impl std::fmt::Display for UnrecoverableReorg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unrecoverable reorg at {}: no note-commitment-tree checkpoint with a scanned block \
             exists below the conflict (requested rewind to {}",
            self.at_height, self.requested
        )?;
        if let Some(safe) = self.safe_rewind_height {
            write!(f, "; storage reported {safe} as its lowest safe target")?;
        }
        f.write_str(")")
    }
}

impl std::error::Error for UnrecoverableReorg {}

/// Download Sapling + Orchard note-commitment subtree roots and hand them to the wallet.
/// Run once at startup (and cheaply repeatable).
pub async fn update_subtree_roots<C: ChainSource>(
    client: &mut C,
    db_data: &mut WriteDb,
) -> anyhow::Result<()> {
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .subtree_roots(ShieldedPool::Sapling)
        .await?
        .into_iter()
        .map(|root| {
            let root_hash = sapling::Node::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_height),
                root_hash,
            ))
        })
        .collect::<std::io::Result<_>>()?;
    db_data.put_sapling_subtree_roots(0, &sapling_roots)?;

    let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> = client
        .subtree_roots(ShieldedPool::Orchard)
        .await?
        .into_iter()
        .map(|root| {
            let root_hash = MerkleHashOrchard::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_height),
                root_hash,
            ))
        })
        .collect::<std::io::Result<_>>()?;
    db_data.put_orchard_subtree_roots(0, &orchard_roots)?;

    // Ironwood has no separate subtree-root seeding pass: the `dw/ironwood-scan-model` upstream
    // populates the Ironwood note-commitment shardtree directly during `put_blocks` (received
    // Ironwood notes are stored as blocks are scanned), and it exposes no `put_ironwood_subtree_roots`
    // API to pre-seed roots from `z_getsubtreesbyindex "ironwood"` the way Sapling/Orchard do. On
    // the short regtest chain this is equivalent; a from-genesis scan builds the tree. If upstream
    // later adds an Ironwood subtree-root writer, reinstate a pass here (gated on NU6.3 being active).

    Ok(())
}

/// The wallet's transparent receive-matching set: every *recorded* receiver (an `addresses` row -
/// exposed receiving/change addresses plus librustzcash's funded-anchored gap rows) together with
/// an in-memory **gap lookahead**: the next `transparent_gap_limit` external indices past the
/// issuance frontier (`max(transparent_initial_scan, highest exposed external index + 1)`),
/// derived from the account's external incoming viewing key but never written to the database.
///
/// The lookahead is what makes `transparent_gap_limit` compose with `transparent_initial_scan`
/// as a BIP-44-style gap. librustzcash anchors its gap window at the last *funded* index only,
/// so without this a from-seed restore with `initial_scan = 70_000, gap_limit = 1_000` would
/// cover exactly `0..70_000`, and a receive at index 70_500 (issued after the floor was declared)
/// could only be recovered by inflating the gap limit to 71_000. With the lookahead the matcher
/// always covers `gap_limit` indices past the frontier; a match on a lookahead address records
/// its `addresses` row first (see [`record_lookahead_address`]), which exposes the index and
/// slides the frontier on the next rebuild - the same funded-chain extension BIP-44 recovery
/// performs past the last used address.
pub struct TransparentMatcher {
    /// The account a lookahead match is recorded against.
    pub account: AccountUuid,
    /// Membership set for matching: recorded receivers plus the lookahead addresses.
    pub all: HashSet<TransparentAddress>,
    /// Lookahead addresses (a subset of `all`) that have no `addresses` row yet, keyed to their
    /// external child index so a match can record the row via `get_address_for_index`.
    pub lookahead: HashMap<TransparentAddress, u32>,
}

impl TransparentMatcher {
    /// The external child index behind `address` when it is a not-yet-recorded lookahead
    /// address; `None` for a recorded receiver (which needs no row created before recording
    /// a receive against it).
    pub fn lookahead_index(&self, address: &TransparentAddress) -> Option<u32> {
        self.lookahead.get(address).copied()
    }
}

/// Record the `addresses` row for a lookahead-matched external index (via
/// `get_address_for_index`, the same primitive the A18 pre-exposure and beyond-gap issuance
/// use). `put_received_transparent_utxo` rejects an output paying an address without a row
/// (`AddressNotRecognized`), so this must run before a lookahead match is recorded. Exposing
/// the index here is correct bookkeeping: `Exposed` covers addresses the wallet handed out
/// *or has seen funded on-chain*, and this is the latter.
pub fn record_lookahead_address(
    db_data: &mut WriteDb,
    account: AccountUuid,
    index: u32,
) -> Result<(), SqliteClientError> {
    db_data
        .get_address_for_index(
            account,
            DiversifierIndex::from(index),
            crate::pools::transparent_extraction_request(),
        )
        .map(|_| ())
}

/// A block-scan-matched transparent receive: the attributable output plus, when it came from a
/// block's coinbase transaction, that full transaction. The coinbase tx is stored alongside the
/// receive (`decrypt_and_store_transaction`) so `zcash_client_sqlite` records
/// `transactions.tx_index = 0` - without it the UTXO would be misclassified as non-coinbase
/// (`IFNULL(tx_index, 1)`), escaping both the 100-block maturity clause and the
/// `CoinbaseFilter::CoinbaseOnly` selection `z_shieldcoinbase` relies on.
pub struct MatchedTransparentReceive {
    pub output: WalletTransparentOutput<AccountUuid>,
    pub coinbase_tx: Option<std::sync::Arc<zcash_primitives::transaction::Transaction>>,
}

/// Parse a fetched raw transaction and store it, marking any of the wallet's transparent outputs
/// it spends as spent (and recording the outgoing history entry). The consensus branch is taken
/// from the height the spend was mined at, which the matcher always knows.
fn store_fetched_tx(
    params: &ZNetwork,
    db_data: &mut WriteDb,
    fetched: &crate::chain::FetchedTx,
    height: u32,
) -> anyhow::Result<()> {
    let mined = BlockHeight::from_u32(fetched.mined_height.unwrap_or(height));
    let tx = zcash_primitives::transaction::Transaction::read(
        &fetched.data[..],
        zcash_protocol::consensus::BranchId::for_height(params, mined),
    )?;
    decrypt_and_store_transaction(params, db_data, &tx, Some(mined))?;
    Ok(())
}

/// A block-scan-matched transparent **spend**: one of the wallet's own unspent outputs was
/// consumed by `spending_txid` at `height`.
///
/// Only the identity is carried. Storing the spend needs the full spending transaction, which
/// neither backend has to hand during the scan (zebra has the parsed block, but fetching once per
/// real wallet spend keeps both backends on one path), so the caller fetches it after the range
/// applies - once per matched spend, an event as rare as the wallet spending money.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedTransparentSpend {
    pub spending_txid: TxId,
    pub height: u32,
}

/// Key for the wallet's unspent transparent outputs: `(funding txid, output index)`. The block
/// scan tests every transparent input against this set, so a spend of a wallet UTXO is found in
/// the block that mines it - no address queries, and no dependence on librustzcash emitting a
/// spend-search request for an address zecd recorded itself.
pub type UnspentOutpoints = HashSet<(TxId, u32)>;

/// Build a [`WalletTransparentOutput`] for `utxo` iff its recipient address is one of the
/// wallet's exposed transparent addresses (`addresses`). Returns `None` for an output paying
/// someone else, or one whose script isn't a recognized p2pkh/p2sh (librustzcash can't attribute
/// those). The funding `height` may be `None` for a mempool (0-conf) output.
///
/// Shared by the block scan (this module) and the actor's mempool path so the two discovery
/// sources stay byte-for-byte consistent.
pub fn owned_transparent_output(
    addresses: &HashSet<TransparentAddress>,
    txid: TxId,
    index: u32,
    value_zat: u64,
    script: Vec<u8>,
    height: Option<u32>,
) -> Option<WalletTransparentOutput<AccountUuid>> {
    use zcash_transparent::address::Script;
    use zcash_transparent::bundle::{OutPoint, TxOut};
    let value = Zatoshis::from_u64(value_zat).ok()?;
    let outpoint = OutPoint::new(*txid.as_ref(), index);
    let txout = TxOut::new(value, Script(zcash_script::script::Code(script)));
    // The valar fork's `from_parts` takes three extra args (recipient_account,
    // recipient_key_scope, funding_account); a chain-discovered UTXO doesn't know them, and
    // `put_received_transparent_utxo` re-derives the owning account, so `None` matches the
    // released 3-arg behavior. `<AccountUuid>` pins the otherwise-unconstrained account type.
    let output = WalletTransparentOutput::from_parts(
        outpoint,
        txout,
        height.map(BlockHeight::from_u32),
        None,
        None,
        None,
    )?;
    addresses
        .contains(output.recipient_address())
        .then_some(output)
}

/// How many consecutive *zero-progress* reconnects [`download_blocks`] tolerates after a
/// client-side h2 load shed before giving up on the range. Any attempt that receives at least
/// one block resets the count, so a download that keeps making progress keeps resuming, and
/// only a range that cannot advance at all surfaces the error.
const MAX_STALLED_STREAM_RESTARTS: u32 = 3;

/// The shielded work a downloaded range carries, counted while it streams in. The download
/// already walks every transaction to count its outputs, so this costs nothing, and it is
/// what turns a per-batch wall clock into something an operator can read: a range of
/// near-empty blocks and a range carrying a transaction burst differ by an order of magnitude
/// per block, and only the shape says which one a slow batch was.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RangeShape {
    /// Blocks received.
    pub blocks: u32,
    /// Compact-block bytes as served (the encoded size held in the cache).
    pub bytes: u64,
    /// Transactions in the range.
    pub txs: u64,
    /// Sapling outputs in the range.
    pub sapling_outputs: u64,
    /// Orchard actions in the range (Ironwood actions included: the compact representation
    /// carries them in the same per-transaction action list).
    pub orchard_actions: u64,
}

/// The progress one [`download_blocks`] call accumulates across however many streaming
/// attempts it takes. Carried between attempts so a reconnect resumes rather than restarts:
/// every block in `blocks` is already held, and the transparent matching state must not be
/// replayed for it.
struct DownloadProgress {
    blocks: MemBlockCache,
    shape: RangeShape,
    received: Vec<MatchedTransparentReceive>,
    spent: Vec<MatchedTransparentSpend>,
    /// The outpoints to watch for spends, seeded from what the wallet already holds and then
    /// **carried forward as this batch is scanned**: a receive matched in an earlier block of
    /// the same batch is not in the database yet (receives are recorded only after the whole
    /// range scans), so without carrying it here a receive and its spend inside one batch
    /// would leave the spend undetected until some later batch happened to re-cover the block,
    /// which never happens, because the scan is forward-only. At the default 10,000-block batch
    /// that is not an edge case: it is every from-seed restore of a wallet whose transparent
    /// history fits in one batch. It is carried across streaming attempts for the same reason
    /// it is carried across blocks: a resumed download must not lose the earlier blocks' state.
    watch: Option<UnspentOutpoints>,
}

/// Where a load-shed reconnect should resume, or `None` once the range has failed
/// [`MAX_STALLED_STREAM_RESTARTS`] consecutive times without advancing.
///
/// `made_progress` is whether the attempt that just failed received at least one block;
/// `last_received` is the highest block now held, and `resume_from` the height the failed
/// attempt started at (the answer when it received nothing at all). Resuming one past the last
/// block held is what keeps the retry cheap: the load shed killed the connection, not the
/// blocks already in hand.
fn plan_load_shed_resume(
    made_progress: bool,
    last_received: Option<BlockHeight>,
    resume_from: BlockHeight,
    stalled_restarts: &mut u32,
) -> Option<BlockHeight> {
    if made_progress {
        *stalled_restarts = 0;
    } else {
        *stalled_restarts += 1;
        if *stalled_restarts > MAX_STALLED_STREAM_RESTARTS {
            return None;
        }
    }
    Some(last_received.map_or(resume_from, |h| h + 1))
}

/// What one [`download_blocks`] call produced: the range's blocks, what the transparent
/// matcher found in them, and the shape of the work they carry.
pub struct DownloadedRange {
    /// The blocks, in the cache the scan reads them from.
    pub blocks: MemBlockCache,
    /// See [`RangeShape`].
    pub shape: RangeShape,
    received: Vec<MatchedTransparentReceive>,
    spent: Vec<MatchedTransparentSpend>,
}

async fn download_blocks<C: ChainSource>(
    client: &mut C,
    scan_range: &ScanRange,
    transparent: Option<&HashSet<TransparentAddress>>,
    unspent: Option<&UnspentOutpoints>,
) -> anyhow::Result<DownloadedRange> {
    info!(range = %scan_range, "fetching compact blocks");
    let range_end = scan_range.block_range().end - 1;
    let mut next = scan_range.block_range().start;
    let mut progress = DownloadProgress {
        blocks: MemBlockCache::new(),
        shape: RangeShape::default(),
        received: vec![],
        spent: vec![],
        watch: unspent.cloned(),
    };
    let mut stalled_restarts = 0u32;

    while next <= range_end {
        let before = progress.blocks.len();
        match download_range_once(client, next, range_end, transparent, &mut progress).await {
            Ok(()) => break,
            // h2's client-side load shed (see `chain::is_h2_load_shed`) kills the connection,
            // not the progress: every block already received stays held, and the next
            // `compact_block_range` reconnects transparently onto a fresh connection with a
            // full frame budget. Eager draining alone cannot rule this out, because the
            // budget is charged as h2's connection task parses frames off the socket - a
            // burst on datacenter bandwidth can exhaust it before the reader task is
            // scheduled at all, however fast it drains. So resume from the first block we do
            // not have instead of failing the whole batch back to the actor, which would
            // restart the range from the same height and hit the same wall.
            Err(e) if crate::chain::is_h2_load_shed(&e) => {
                let made_progress = progress.blocks.len() > before;
                let last_received = progress.blocks.last_height();
                let Some(resume_at) = plan_load_shed_resume(
                    made_progress,
                    last_received,
                    next,
                    &mut stalled_restarts,
                ) else {
                    return Err(e.context(
                        "block download made no progress across repeated h2 load-shed reconnects",
                    ));
                };
                next = resume_at;
                warn!(
                    resume_at = u32::from(next),
                    "client-side h2 load shed killed the block stream; reconnecting and resuming"
                );
            }
            Err(e) => return Err(e),
        }
    }

    progress.shape.blocks = progress.blocks.len() as u32;
    progress.shape.bytes = progress.blocks.byte_len();
    Ok(DownloadedRange {
        blocks: progress.blocks,
        shape: progress.shape,
        received: progress.received,
        spent: progress.spent,
    })
}

/// One streaming attempt of [`download_blocks`]: fetch `[next, range_end]` and fold each block
/// into `progress`. On a stream error everything appended so far is already held, so the
/// caller can resume after the last entry.
async fn download_range_once<C: ChainSource>(
    client: &mut C,
    next: BlockHeight,
    range_end: BlockHeight,
    transparent: Option<&HashSet<TransparentAddress>>,
    progress: &mut DownloadProgress,
) -> anyhow::Result<()> {
    let mut stream = client
        .compact_block_range(next, range_end, transparent.is_some())
        .await?;

    while let Some((block, t_outs, t_ins)) = stream.next().await? {
        // The per-block level for diagnosing "stuck at height N" in the field without a
        // custom build; costs one disabled-level check per block when filtered out.
        tracing::trace!(
            height = u32::from(block.height()),
            txs = block.vtx.len(),
            transparent_outputs = t_outs.len(),
            transparent_inputs = t_ins.len(),
            "downloaded block"
        );
        for tx in &block.vtx {
            progress.shape.sapling_outputs += tx.outputs.len() as u64;
            progress.shape.orchard_actions += tx.actions.len() as u64;
        }
        progress.shape.txs += block.vtx.len() as u64;

        // Match this block's transparent outputs against the wallet's exposed addresses. This is
        // O(outputs-in-block) with a hash-set membership test per output, independent of how many
        // addresses the wallet holds - the property that lets an exchange track ~100k addresses
        // without per-address requests. The full block was already fetched for the shielded scan,
        // so there is no extra round-trip.
        if let Some(addresses) = transparent {
            for u in t_outs {
                if let Some(output) = owned_transparent_output(
                    addresses,
                    u.txid,
                    u.index,
                    u.value_zat,
                    u.script,
                    u.height,
                ) {
                    // Watch the new output for a spend later in this same batch.
                    if let Some(w) = progress.watch.as_mut() {
                        w.insert((*output.outpoint().txid(), output.outpoint().n()));
                    }
                    progress.received.push(MatchedTransparentReceive {
                        output,
                        coinbase_tx: u.coinbase_tx,
                    });
                }
            }
        }

        // Match this block's transparent inputs against the wallet's unspent outpoints - the
        // spend-side mirror of the output matching above, and the only thing that discovers a
        // transparent spend the wallet did not author itself. Same cost model: O(inputs-in-block)
        // with an O(1) membership test, bounded by outputs the wallet actually holds rather than
        // by addresses it has issued, and no extra request (the inputs ride the block that was
        // already fetched).
        // Outputs are matched before inputs above, so a transaction spending an output the
        // wallet received earlier in this same block is caught too. `remove` both tests
        // membership and retires the outpoint, so one spend is recorded once however many of the
        // wallet's outputs the transaction consumes.
        if let Some(w) = progress.watch.as_mut() {
            for i in t_ins {
                if w.remove(&(i.prevout_txid, i.prevout_index)) {
                    let matched = MatchedTransparentSpend {
                        spending_txid: i.spending_txid,
                        height: i.height,
                    };
                    if !progress.spent.contains(&matched) {
                        progress.spent.push(matched);
                    }
                }
            }
        }

        let height = block.height();
        progress.blocks.push(height, block.encode_to_vec());
    }
    Ok(())
}

async fn download_chain_state<C: ChainSource>(
    client: &mut C,
    block_height: BlockHeight,
) -> anyhow::Result<ChainState> {
    let tree_state = client.tree_state(block_height).await?;
    Ok(tree_state.to_chain_state()?)
}

/// One batch downloaded ahead of the scan that will consume it.
///
/// The sync loop alternates a download, which waits on the upstream and the network, with a
/// scan, which is this host's CPU and its wallet database - and neither overlapped the other,
/// so each sat idle for the whole of the other's turn. Against a lightwalletd the download is a
/// small share of a batch; against a full node, which has no compact-block range request and is
/// asked block by block, it was over a third (measured: 249 s to 184 s for the same restore
/// once the next range was fetched while the current one scanned).
///
/// The prefetch is speculative - it guesses that the scan will leave the following range next
/// in line ([`next_range_guess`]) - so it carries the range it fetched, and a guess that does
/// not match what `suggest_scan_ranges` asks for next is simply dropped. That is what makes it
/// safe across a reorg: a rewind changes the next range, the guess misses, and the batch
/// downloads normally.
pub struct Prefetched {
    /// The range these blocks cover.
    pub range: ScanRange,
    /// The blocks, and the shape of what was fetched.
    pub downloaded: DownloadedRange,
}

/// Fetch one range for the prefetch. Shielded-only by construction: the transparent matcher
/// needs the actor's address and outpoint sets, which change as batches record receives, so a
/// detached task must not match against a snapshot of them. The actor only spawns a prefetch
/// for a wallet without transparent receiving.
pub async fn prefetch_range<C: ChainSource>(
    client: &mut C,
    range: ScanRange,
) -> anyhow::Result<Prefetched> {
    let downloaded = download_blocks(client, &range, None, None).await?;
    // A short range is not an error - the upstream may simply not have the blocks yet - but it
    // is not usable either, because the scan expects the whole range it asked for.
    if downloaded.blocks.len() != range.len() {
        anyhow::bail!(
            "prefetch of {range} received {} block(s), expected {}",
            downloaded.blocks.len(),
            range.len()
        );
    }
    Ok(Prefetched { range, downloaded })
}

/// A prefetch in flight. Dropping it aborts the download: an actor that stops syncing (a
/// shutdown, a halt) must not leave a detached task streaming a range nobody will scan.
pub struct PrefetchTask(Option<tokio::task::JoinHandle<anyhow::Result<Prefetched>>>);

impl PrefetchTask {
    /// Run `download` on a detached task.
    pub fn spawn<F>(download: F) -> Self
    where
        F: Future<Output = anyhow::Result<Prefetched>> + Send + 'static,
    {
        Self(Some(tokio::spawn(download)))
    }

    /// Wait for the download. A failed or cancelled prefetch is not an error - the batch
    /// downloads its range normally, and the upstream's own failure surfaces there - so it is
    /// logged at DEBUG and reported as no prefetch.
    pub async fn finish(mut self) -> Option<Prefetched> {
        let handle = self.0.take()?;
        match handle.await {
            Ok(Ok(prefetched)) => Some(prefetched),
            Ok(Err(e)) => {
                tracing::debug!("prefetch failed, downloading the range directly: {e:#}");
                None
            }
            Err(e) => {
                tracing::debug!("prefetch task did not finish: {e}");
                None
            }
        }
    }
}

impl Drop for PrefetchTask {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// How [`sync_one_batch`] starts the next range's download: a closure that spawns the fetch on
/// a fresh upstream handle. The engine is generic over the chain source and holds no handle of
/// its own to spawn with, so the caller (the actor, which holds the shared connection) supplies
/// the spawn.
pub type PrefetchSpawner<'a> = &'a (dyn Fn(ScanRange) -> PrefetchTask + Sync);

/// The range the next batch will take, computed from the ranges as they stand *before* the
/// current batch is scanned - which is what lets the fetch start while the scan runs.
///
/// The next batch's selection is the one [`sync_one_batch`] makes, and the only thing the scan
/// changes about it is retiring the range now being scanned. So: take what is left of the
/// highest-priority range after the current batch, and chunk it the same way. A guess made
/// this way is right whenever the scan retires its range and leaves the priorities alone,
/// which is the ordinary case; anything else - a reorg, a new tip-priority range - makes it
/// miss, and a miss costs only the fetch it wasted.
///
/// `None` when the current batch finishes the range in hand, and when it is a `Verify`: those
/// are small, they come first, and what follows one depends on what the verification finds.
pub fn next_range_guess(
    scan_ranges: &[ScanRange],
    scanning: &ScanRange,
    batch_size: u32,
) -> Option<ScanRange> {
    let first = scan_ranges.first()?;
    if first.priority() == ScanPriority::Verify {
        return None;
    }
    let (_, rest) = first.split_at(scanning.block_range().end)?;
    match rest.split_at(rest.block_range().start + batch_size) {
        Some((next, _)) => Some(next),
        None => Some(rest),
    }
}

/// Rewind the wallet to `requested` (chosen below the continuity break at `at_height`),
/// retrying at the shallow bound `at_height - 2` when no valid truncation target exists at
/// or below `requested`. Returns the height actually rewound to.
///
/// The retry leans on the documented `WalletWrite::truncate_to_height` contract:
/// implementations rewind to the nearest valid target *at or below* the requested height
/// and return it (`zcash_client_sqlite` picks the highest scanned block carrying both
/// sapling and orchard note-commitment-tree checkpoints), so one shallower call is the
/// entire "find a recoverable height" search. The stored block at `at_height - 1`
/// contradicts the new chain, so any useful rewind must remove it - hence the strict
/// `at_height - 2` bound, which also guarantees progress: each pass strictly shrinks the
/// scanned chain instead of re-truncating to the same stale block forever. Without the
/// retry a young wallet wedges: the deep rewind target can land below every checkpointed
/// block (the birthday anchor has no `blocks` row), `truncate_to_height` errors with
/// `RequestedRewindInvalid`, and the same scan range fails identically on every attempt -
/// the bug upstream's `sync::run` still has (see the module docs).
///
/// The error's `safe_rewind_height` is deliberately ignored: upstream computes it as the
/// minimum checkpoint height *without* requiring a scanned block there, so it may name the
/// blocks-row-less birthday anchor (itself an invalid target), and any height below the
/// already-failed `requested` fails a fortiori.
///
/// Lineage: mirrored in zkv's `internal/sync.rs` - port fixes both ways.
///
/// TODO(upstream): the one remaining storage-backend coupling here is matching the
/// concrete `SqliteClientError::RequestedRewindInvalid` - `zcash_client_backend`'s
/// `WalletWrite` has no trait-level "rewind invalid" error contract, so reorg recovery is
/// structurally tied to the sqlite backend. With non-SQLite `WalletDb` backends planned
/// (PostgreSQL), propose upstream a trait-level error (or a `truncate_to_height` variant
/// that reports "no valid target at or below" portably) and switch this match to it.
fn perform_rewind(
    db_data: &mut WriteDb,
    at_height: BlockHeight,
    requested: BlockHeight,
    base_requested: BlockHeight,
) -> anyhow::Result<BlockHeight> {
    let safe_rewind_height = match db_data.truncate_to_height(requested) {
        Ok(h) => return Ok(h),
        Err(SqliteClientError::RequestedRewindInvalid {
            safe_rewind_height, ..
        }) => safe_rewind_height,
        Err(e) => return Err(e.into()),
    };
    // A grown margin (see `next_reorg_margin`) can ask to go deeper than the wallet's retained
    // checkpoints reach, on a wallet that could still have rewound the base distance. Try that
    // before the ladder below, which escalates *upward* toward the conflict and would otherwise
    // turn a refused deep request into two-block steps - worse than never having grown.
    if base_requested < at_height && base_requested > requested {
        match db_data.truncate_to_height(base_requested) {
            Ok(h) => {
                info!("Rewound to {h} (no valid target at or below {requested})");
                return Ok(h);
            }
            Err(SqliteClientError::RequestedRewindInvalid { .. }) => {}
            Err(e) => return Err(e.into()),
        }
    }
    // Candidates, in order. The shallow bound must be *strictly below* the known-stale block at
    // `at_height - 1`, or the conflicting block survives the rewind and the next batch re-hits it.
    // The storage layer's own `safe_rewind_height` is tried too, but only when it is below what it
    // just refused: it is documented as "the lowest height it is possible to safely rewind to",
    // and it can name the very height that failed (measured: `truncate_to_height(0)` refused with
    // `safe_rewind_height: Some(0)`), which would retry the identical call forever.
    let shallow = BlockHeight::from(u32::from(at_height).saturating_sub(2));
    let candidates = [
        Some(shallow),
        safe_rewind_height.filter(|h| *h < requested && *h < shallow),
    ];
    for target in candidates.into_iter().flatten() {
        match db_data.truncate_to_height(target) {
            Ok(h) => {
                info!("Shallow rewind to {h} (no valid target at or below {requested})");
                return Ok(h);
            }
            Err(SqliteClientError::RequestedRewindInvalid { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    // No scanned block below the conflict can be rewound to: the reorg is deeper than the
    // wallet's rewindable history. Retrying cannot help - the actor halts this wallet's sync on
    // this error rather than re-attempting it forever - and recovery is a from-birthday resync.
    Err(UnrecoverableReorg {
        at_height,
        requested,
        safe_rewind_height,
    }
    .into())
}

/// The result of scanning one downloaded range.
pub struct ScanOutcome {
    /// Whether the highest-priority suggested scan range changed materially (caller may want to
    /// re-evaluate what to scan next).
    pub ranges_changed: bool,
    /// Whether a continuity (reorg) error was caught and the wallet rewound *instead of* applying
    /// the range. When set, the range's blocks were **not** scanned, so any transparent receives
    /// harvested from them must be discarded (they belong to the abandoned fork).
    pub reorged: bool,
}

/// The rewind margin a wallet starts from, and returns to after any clean scan: how far below a
/// detected continuity break to truncate. Upstream's own example heuristic.
pub const REORG_BASE_MARGIN: u32 = 10;

/// The largest rewind margin the doubling in [`next_reorg_margin`] will reach. One batch is the
/// natural ceiling - rewinding further than a batch would scan back is all cost and no benefit -
/// and it also bounds how much work a mistakenly-grown margin can throw away.
pub const REORG_MAX_MARGIN: u32 = DEFAULT_BATCH_SIZE;

/// The margin to use after a scan pass, given the one just used and whether that pass hit a
/// reorg.
///
/// A wallet only ever learns about a fork one block at a time, at its own tip: the scanner
/// reports a continuity break at the first block whose `prev_hash` disagrees, and nothing tells
/// it how deep the disagreement goes. With a fixed margin, recovery therefore walks the fork
/// backwards a fixed step per round trip - and each round trip is a tree-state fetch, a block
/// download and a truncation. A pool that rolled its node back 1,835 blocks watched that take 62
/// rounds and about ten minutes.
///
/// Doubling turns that walk into a logarithmic one (1,835 blocks becomes about eight rounds)
/// while leaving the common case alone: an ordinary one- or two-block reorg is resolved by the
/// first rewind, and the margin resets, so a wallet that is keeping up never grows one. The cost
/// of overshooting is rescanning blocks the wallet would have scanned anyway.
pub fn next_reorg_margin(current: u32, reorged: bool) -> u32 {
    if reorged {
        current.saturating_mul(2).min(REORG_MAX_MARGIN)
    } else {
        REORG_BASE_MARGIN
    }
}

/// Scan a downloaded range; handle continuity (reorg) errors by rewinding. See [`ScanOutcome`].
///
/// On a reorg the range's blocks are simply not applied: they live only in `blocks`, which the
/// caller drops with the batch, so there is nothing on disk to clean up and no cache index to
/// keep consistent with the rewind.
fn scan_blocks(
    params: &ZNetwork,
    blocks: &MemBlockCache,
    db_data: &mut WriteDb,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
    reorg_margin: u32,
) -> anyhow::Result<ScanOutcome> {
    info!(range = %scan_range, "scanning blocks");
    let scan_result = scan_cached_blocks(
        params,
        blocks,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            let margin = reorg_margin.max(REORG_BASE_MARGIN);
            let requested = err.at_height().saturating_sub(margin);
            info!(
                margin,
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                requested
            );
            // NB: truncation requires a note-commitment-tree checkpoint, and per-block
            // checkpoints exist only for scanned blocks that carried shielded outputs
            // (virtually all real blocks). `perform_rewind` falls back to the nearest
            // valid checkpoint when the requested height has none.
            let base = err.at_height().saturating_sub(REORG_BASE_MARGIN);
            perform_rewind(db_data, err.at_height(), requested, base)?;
            Ok(ScanOutcome {
                ranges_changed: true,
                reorged: true,
            })
        }
        Ok(_) => {
            let latest_ranges = db_data.suggest_scan_ranges()?;
            let ranges_changed = latest_ranges
                .first()
                .map(|range| range.priority() > scan_range.priority())
                .unwrap_or(false);
            Ok(ScanOutcome {
                ranges_changed,
                reorged: false,
            })
        }
        // Any other scan failure is an apply-side error: the blocks arrived, the wallet DB
        // couldn't absorb them. Typed so the actor's persistent-failure diagnostics can
        // distinguish it from a transport error (see [`WalletApplyError`]).
        Err(e) => Err(anyhow::Error::new(WalletApplyError(format!("{e:?}")))),
    }
}

/// Where the wall clock went inside one [`sync_one_batch`] call, plus the shape of the work
/// that consumed it.
///
/// The sync loop's two phases bill to entirely different resources - the download to the
/// upstream and the network, the scan to this host's CPU and its wallet database - and a
/// single "batch took N seconds" line cannot tell them apart, so an operator watching a slow
/// restore could not tell whether to blame their upstream or their hardware, and neither could
/// a benchmark. This carries the split out to the caller, which logs it per batch and
/// accumulates it on [`crate::wallet::SyncTotals`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BatchTimings {
    /// Streaming the compact blocks into the cache, or taking a prefetched range.
    pub download: std::time::Duration,
    /// The `tree_state` round trip for the block below the range.
    pub tree_state: std::time::Duration,
    /// `scan_cached_blocks`: trial decryption, note-commitment tree insertion, and the
    /// database write, which this level cannot separate.
    pub scan: std::time::Duration,
    /// Recording transparent receives and spends matched during the download.
    pub transparent: std::time::Duration,
    /// Whether this batch's blocks had already been fetched while the previous one scanned,
    /// so `download` is the cost of taking them rather than of fetching them.
    pub prefetch_hit: bool,
    /// The work the range carried.
    pub shape: RangeShape,
}

impl BatchTimings {
    /// Everything [`sync_one_batch`] spent on the batch, whether or not the range applied.
    pub fn total(&self) -> std::time::Duration {
        self.download + self.tree_state + self.scan + self.transparent
    }

    /// Blocks per second over the whole batch, or `0.0` for an empty/instant batch.
    pub fn blocks_per_sec(&self) -> f64 {
        let secs = self.total().as_secs_f64();
        if secs > 0.0 {
            f64::from(self.shape.blocks) / secs
        } else {
            0.0
        }
    }
}

/// Outcome of one sync batch: whether a batch was scanned (so the caller should call again), and
/// how many transparent receives were recorded from the block scan (so the actor can refresh its
/// exposed-address set - a recorded receive may have extended the transparent gap).
pub struct BatchOutcome {
    pub worked: bool,
    /// Whether this batch hit a chain reorg and rewound instead of applying the range. The
    /// actor uses it to grow its rewind margin while a deep reorg is being walked back, and to
    /// reset it on the first clean batch (see [`next_reorg_margin`]).
    pub reorged: bool,
    pub transparent_recorded: usize,
    /// Spends of the wallet's own transparent outputs discovered by matching this batch's
    /// transparent inputs against its unspent outpoints.
    pub transparent_spends_recorded: usize,
    /// Where this batch's wall clock went. Zero on the no-work path.
    pub timings: BatchTimings,
    /// A download of the range the next batch is expected to take, started before this
    /// batch's scan so it overlaps it. `None` when there was nothing to guess at, when the
    /// caller supplied no spawner, or when a reorg invalidated the guess. See [`Prefetched`].
    pub next_prefetch: Option<PrefetchTask>,
}

/// What [`sync_one_batch`] needs beyond the client and the wallet database.
pub struct BatchParams<'a> {
    /// The wallet's transparent receive matcher when transparent receiving is enabled (`None`
    /// for shielded-only wallets, which skips transparent extraction entirely). When present,
    /// each scanned block's transparent outputs are matched against it and recorded as receives
    /// via `put_received_transparent_utxo` after the shielded scan succeeds; a match on a
    /// gap-lookahead address records its `addresses` row first ([`record_lookahead_address`]).
    pub transparent: Option<&'a TransparentMatcher>,
    /// The wallet's unspent transparent outpoints, matched against each block's inputs.
    pub unspent: Option<&'a UnspentOutpoints>,
    /// How far below a continuity break to rewind (see [`next_reorg_margin`]).
    pub reorg_margin: u32,
    /// Blocks per batch (`[sync] batch_size`).
    pub batch_size: u32,
    /// A download of the range this batch is expected to take, started by the previous one.
    /// Used only if it covers exactly the range this batch selects.
    pub prefetched: Option<Prefetched>,
    /// How to start the next range's download while this batch scans; `None` runs the loop
    /// the plain way, one phase at a time.
    pub prefetch: Option<PrefetchSpawner<'a>>,
}

/// Process at most one batch of work. `worked` is `true` if a batch was scanned (caller should
/// call again), `false` if there are no pending scan ranges (wallet is caught up).
pub async fn sync_one_batch<C: ChainSource>(
    client: &mut C,
    params: &ZNetwork,
    db_data: &mut WriteDb,
    batch: BatchParams<'_>,
) -> anyhow::Result<BatchOutcome> {
    let scan_ranges = db_data.suggest_scan_ranges()?;
    tracing::debug!(
        "suggest_scan_ranges -> {} range(s): {:?}",
        scan_ranges.len(),
        scan_ranges
            .iter()
            .map(|r| {
                (
                    u32::from(r.block_range().start),
                    u32::from(r.block_range().end),
                    r.priority(),
                )
            })
            .collect::<Vec<_>>()
    );
    let Some(first) = scan_ranges.first() else {
        return Ok(BatchOutcome {
            worked: false,
            reorged: false,
            transparent_recorded: 0,
            transparent_spends_recorded: 0,
            timings: BatchTimings::default(),
            next_prefetch: None,
        });
    };

    // A `Verify` range is always returned first and is small; scan it whole. Otherwise scan
    // the first `batch_size`-block chunk of the highest-priority range.
    let scan_range = if first.priority() == ScanPriority::Verify {
        first.clone()
    } else {
        match first.split_at(first.block_range().start + batch.batch_size) {
            Some((cur, _next)) => cur,
            None => first.clone(),
        }
    };

    let mut timings = BatchTimings::default();

    // Was the range downloaded ahead of time, while the previous batch was scanning? Only if
    // the guess matches exactly: a rewind, a priority change or a re-planned range all make it
    // miss, and a miss costs nothing but the fetch it wasted.
    let t_download = std::time::Instant::now();
    let downloaded = match batch.prefetched.filter(|p| p.range == scan_range) {
        Some(prefetched) => {
            info!(range = %scan_range, "taking prefetched compact blocks");
            timings.prefetch_hit = true;
            prefetched.downloaded
        }
        None => {
            download_blocks(
                client,
                &scan_range,
                batch.transparent.map(|m| &m.all),
                batch.unspent,
            )
            .await?
        }
    };
    timings.download = t_download.elapsed();
    timings.shape = downloaded.shape;
    let DownloadedRange {
        blocks,
        received,
        spent,
        ..
    } = downloaded;

    // Start fetching the next range now, so the upstream works while this host scans. It has
    // to happen *here*, between the download and the scan: spawned after the scan it would
    // have nothing to overlap with. (That is exactly the mistake the first version of this
    // made - every phase timing improved and the wall clock did not move.)
    let mut next_prefetch = batch
        .prefetch
        .and_then(|spawn| next_range_guess(&scan_ranges, &scan_range, batch.batch_size).map(spawn));

    // Fetch the prior block's chain state and scan.
    let mut tree_state_elapsed = std::time::Duration::ZERO;
    let result = async {
        // Never request the tree state below height 1: lightwalletd treats BlockId height 0 as
        // "unspecified" and rejects it, and there's no pre-genesis tree state. On a genesis-
        // adjacent range (fresh regtest) `start - 1` would be 0; clamp to 1 (mirrors init.rs).
        let start = u32::from(scan_range.block_range().start);
        let prior_height = BlockHeight::from(start.saturating_sub(1).max(1));
        let t_tree = std::time::Instant::now();
        let chain_state = download_chain_state(client, prior_height).await?;
        tree_state_elapsed = t_tree.elapsed();

        // `scan_cached_blocks` is CPU-bound; keep the async runtime healthy.
        let t_scan = std::time::Instant::now();
        let outcome = tokio::task::block_in_place(|| {
            scan_blocks(
                params,
                &blocks,
                db_data,
                &chain_state,
                &scan_range,
                batch.reorg_margin,
            )
        })?;
        timings.scan = t_scan.elapsed();
        Ok::<ScanOutcome, anyhow::Error>(outcome)
    }
    .await;
    timings.tree_state = tree_state_elapsed;
    // The batch's blocks are done with, whether or not the scan applied them.
    drop(blocks);
    let outcome = result?;

    let t_transparent = std::time::Instant::now();

    // Record the transparent receives matched during download - but only when the range was
    // actually applied. On a reorg the wallet rewound instead of scanning these blocks, so the
    // outputs belong to the abandoned fork and must be dropped (the replacement chain's blocks
    // re-surface the real receives on the next pass). `put_received_transparent_utxo` is
    // idempotent, so re-recording across overlapping passes is harmless.
    let mut transparent_recorded = 0;
    let mut transparent_spends_recorded = 0;
    if !outcome.reorged {
        let mut coinbase_stored: HashSet<TxId> = HashSet::new();
        let mut record_throttle =
            crate::progress::ProgressThrottle::new(TRANSPARENT_RECORD_LOG_INTERVAL, 0);
        for matched in &received {
            let output = &matched.output;
            // A gap-lookahead match has no `addresses` row yet; record (and thereby expose) it
            // first, or the receive below would be rejected as `AddressNotRecognized`.
            if let Some(matcher) = batch.transparent {
                if let Some(index) = matcher.lookahead_index(output.recipient_address()) {
                    if let Err(e) = record_lookahead_address(db_data, matcher.account, index) {
                        warn!(
                            "recording lookahead transparent address at index {index} \
                             failed: {e}"
                        );
                        continue;
                    }
                }
            }
            // Recording a receive is CPU-bound out of proportion to its size: librustzcash's
            // gap maintenance re-derives the wallet's entire external gap window on every
            // recorded transparent output (and again for each already-recorded output of the
            // same transaction). Under the default gap limit this is sub-millisecond, but a
            // wide window (warned about via `TRANSPARENT_GAP_LIMIT_SEVERE`) turns each put
            // into seconds of derivation, so run it under `block_in_place` like the block scan -
            // and emit a throttled progress line so a slow pass reads as gap maintenance at
            // work rather than a silent multi-minute stall (a 71000-wide window in the field
            // froze a restore for an hour with no log output between batches).
            let put = tokio::task::block_in_place(|| db_data.put_received_transparent_utxo(output));
            match put {
                Ok(_) => transparent_recorded += 1,
                Err(e) => {
                    warn!(
                        "recording transparent receive {}:{} failed: {e}",
                        output.outpoint().txid(),
                        output.outpoint().n(),
                    );
                    continue;
                }
            }
            if let Some(w) = record_throttle.tick(transparent_recorded as u64) {
                info!(
                    recorded = transparent_recorded,
                    total = received.len(),
                    elapsed_secs = w.elapsed_secs as u64,
                    "recording transparent receives from block scan (each receive re-derives \
                     the transparent gap window; keep [pools] transparent_gap_limit small and \
                     use transparent_initial_scan for restore depth)"
                );
            }
            // A coinbase receive also stores its full transaction, so the wallet DB learns
            // `tx_index = 0` (`put_tx_data` derives it from `Bundle::is_coinbase`). This is what
            // makes librustzcash's 100-block coinbase-maturity clause and `CoinbaseFilter`
            // partition apply to the UTXO - recorded bare, it would count as non-coinbase and be
            // offered for spending while immature. Once per coinbase tx, not per output.
            if let Some(tx) = &matched.coinbase_tx {
                if coinbase_stored.insert(tx.txid()) {
                    if let Err(e) =
                        decrypt_and_store_transaction(params, db_data, tx, output.mined_height())
                    {
                        warn!(
                            "storing coinbase tx {} for a matched receive failed: {e}",
                            tx.txid()
                        );
                    }
                }
            }
        }
        if transparent_recorded > 0 {
            info!("recorded {transparent_recorded} transparent receive(s) from block scan");
        }

        // Record the matched spends. Storing the spending transaction is what marks the wallet's
        // UTXO spent (and produces the outgoing history entry); until then the wallet reports a
        // balance it no longer holds and can select the output for a send that fails at
        // broadcast. Gated on `!outcome.reorged` for the same reason as the receives: on a
        // rewind these blocks were never applied, and the replacement chain re-surfaces any real
        // spend on a later pass.
        for matched in &spent {
            let fetched = match client.fetch_tx(matched.spending_txid).await {
                Ok(Some(tx)) => tx,
                Ok(None) => {
                    warn!(
                        "upstream does not know transparent-spending tx {}; the spend \
                         will be retried when the block is rescanned",
                        matched.spending_txid
                    );
                    continue;
                }
                Err(e) => {
                    warn!(
                        "fetching transparent-spending tx {} failed: {e}",
                        matched.spending_txid
                    );
                    continue;
                }
            };
            let stored = tokio::task::block_in_place(|| {
                store_fetched_tx(params, db_data, &fetched, matched.height)
            });
            match stored {
                Ok(()) => {
                    transparent_spends_recorded += 1;
                    info!(
                        "recorded transparent spend {} at height {} from block scan",
                        matched.spending_txid, matched.height
                    );
                }
                Err(e) => warn!(
                    "storing transparent-spending tx {} failed: {e}",
                    matched.spending_txid
                ),
            }
        }
    } else {
        // A reorg invalidates the guess: the rewind changes what comes next, so drop the fetch
        // (which aborts it) rather than let the next batch test it against a range it can no
        // longer want.
        next_prefetch = None;
    }

    timings.transparent = t_transparent.elapsed();

    Ok(BatchOutcome {
        worked: true,
        reorged: outcome.reorged,
        transparent_recorded,
        transparent_spends_recorded,
        timings,
        next_prefetch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::frontier::Frontier;
    use orchard::note::ExtractedNoteCommitment;
    use secrecy::SecretVec;
    use zcash_client_backend::data_api::AccountBirthday;
    use zcash_client_backend::proto::compact_formats as pb;
    use zcash_primitives::block::BlockHash;

    type OrchardFrontier =
        Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>;

    /// The standard p2pkh `scriptPubKey` for a 20-byte key hash:
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
    fn p2pkh_script(hash: [u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// The spend matcher fires exactly on the wallet's own unspent outpoints, and dedupes a
    /// transaction that consumes several of them into one recorded spend (storing the spending
    /// transaction once marks every input it spends).
    #[test]
    fn transparent_spends_match_only_the_wallets_unspent_outpoints() {
        let mine_a = TxId::from_bytes([0x11u8; 32]);
        let mine_b = TxId::from_bytes([0x22u8; 32]);
        let theirs = TxId::from_bytes([0x33u8; 32]);
        let spender = TxId::from_bytes([0xAAu8; 32]);

        let mut unspent: UnspentOutpoints = HashSet::new();
        unspent.insert((mine_a, 0));
        unspent.insert((mine_b, 7));

        // A spend of someone else's output, and of an index the wallet does not hold, are ignored.
        assert!(!unspent.contains(&(theirs, 0)));
        assert!(!unspent.contains(&(mine_a, 1)));
        // Both of the wallet's outpoints match, including a non-zero index.
        assert!(unspent.contains(&(mine_a, 0)));
        assert!(unspent.contains(&(mine_b, 7)));

        // The dedupe the download loop performs: one tx spending both wallet outpoints yields a
        // single MatchedTransparentSpend, so the spending tx is fetched and stored once.
        let candidates = [
            (mine_a, 0u32),
            (mine_b, 7u32),
            (theirs, 0u32),
            (mine_a, 1u32),
        ];
        let mut matched: Vec<MatchedTransparentSpend> = Vec::new();
        for (prevout_txid, prevout_index) in candidates {
            if unspent.contains(&(prevout_txid, prevout_index)) {
                let m = MatchedTransparentSpend {
                    spending_txid: spender,
                    height: 42,
                };
                if !matched.contains(&m) {
                    matched.push(m);
                }
            }
        }
        assert_eq!(
            matched,
            vec![MatchedTransparentSpend {
                spending_txid: spender,
                height: 42,
            }],
            "two wallet inputs in one tx must collapse to a single recorded spend"
        );
    }

    /// A receive and its spend inside a single scan batch. The database still knows nothing about
    /// the receive while the batch is being downloaded (receives are recorded only once the whole
    /// range scans), so the watch set has to carry it forward - otherwise the spend is missed and,
    /// the scan being forward-only, never looked at again. With BATCH_SIZE at 10_000 blocks this
    /// is the ordinary from-seed restore, not a corner case.
    #[test]
    fn a_spend_in_the_same_batch_as_its_receive_is_still_matched() {
        let funding = TxId::from_bytes([0x44u8; 32]);
        let spender = TxId::from_bytes([0x55u8; 32]);

        // The wallet starts empty, exactly as a fresh restore does.
        let mut watch: UnspentOutpoints = HashSet::new();
        assert!(
            !watch.remove(&(funding, 0)),
            "nothing to match before the receive is seen"
        );

        // Block N of the batch: the receive is matched and carried forward.
        watch.insert((funding, 0));
        // Block N+k of the same batch: the spend is matched against the carried-forward outpoint.
        assert!(
            watch.remove(&(funding, 0)),
            "the spend must match the receive carried forward within the batch"
        );
        // And retiring it means a second input naming the same outpoint cannot double-record.
        assert!(!watch.remove(&(funding, 0)));
        let _ = spender;
    }

    /// The receive matcher attributes a transparent output to the wallet iff its recipient address
    /// is in the exposed set, honors the (optional) mined height, and rejects unrecognized scripts -
    /// the shared core of the block-scan and mempool discovery paths.
    #[test]
    fn owned_transparent_output_matches_only_the_wallets_addresses() {
        let mine = [0x11u8; 20];
        let theirs = [0x22u8; 20];
        let txid = TxId::from_bytes([0xABu8; 32]);
        let mut set = HashSet::new();
        set.insert(TransparentAddress::PublicKeyHash(mine));

        // An output paying our address, mined at height 100, is attributed with that height.
        let got = owned_transparent_output(&set, txid, 0, 50_000, p2pkh_script(mine), Some(100))
            .expect("output paying the wallet is recognized");
        assert_eq!(
            got.recipient_address(),
            &TransparentAddress::PublicKeyHash(mine)
        );
        assert_eq!(got.mined_height(), Some(BlockHeight::from_u32(100)));

        // The same output with no height is an unmined (0-conf / mempool) UTXO.
        let unmined = owned_transparent_output(&set, txid, 0, 50_000, p2pkh_script(mine), None)
            .expect("a 0-conf output is still recognized");
        assert_eq!(unmined.mined_height(), None);

        // An output paying someone else is not ours.
        assert!(
            owned_transparent_output(&set, txid, 1, 50_000, p2pkh_script(theirs), Some(100))
                .is_none(),
            "an output to a foreign address is not attributed"
        );

        // A non-standard script has no recipient address librustzcash can attribute.
        assert!(
            owned_transparent_output(&set, txid, 2, 50_000, vec![0x6a, 0x00], Some(100)).is_none(),
            "a non-standard script is rejected"
        );
    }

    /// A deterministic fake block hash: `tag` distinguishes chains, `i` the height.
    fn fake_hash(tag: u8, i: u32) -> [u8; 32] {
        let mut h = [tag; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        h
    }

    /// A small, canonical Pallas-base-field encoding (the scanner must parse every cmx to
    /// insert it into the note commitment tree, so the bytes can't be arbitrary).
    fn cmx_bytes(tag: u8, i: u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        b[4] = tag;
        b
    }

    /// Fabricate a compact block carrying exactly one Orchard action (so, like virtually
    /// every real block, it leaves a note-commitment-tree checkpoint the wallet can rewind
    /// to).
    fn compact_block(
        height: u32,
        hash: [u8; 32],
        prev: [u8; 32],
        cmx: [u8; 32],
        orchard_tree_size: u32,
    ) -> pb::CompactBlock {
        let action = pb::CompactOrchardAction {
            nullifier: cmx_bytes(0xEE, height).to_vec(),
            cmx: cmx.to_vec(),
            // Not a valid Pallas point; trial decryption fails gracefully (not ours).
            ephemeral_key: vec![0u8; 32],
            ciphertext: vec![0u8; 52],
        };
        let tx = pb::CompactTx {
            index: 0,
            txid: cmx_bytes(0xDD, height).to_vec(),
            actions: vec![action],
            ..Default::default()
        };
        pb::CompactBlock {
            height: u64::from(height),
            hash: hash.to_vec(),
            prev_hash: prev.to_vec(),
            time: 1_700_000_000 + height,
            header: vec![],
            vtx: vec![tx],
            chain_metadata: Some(pb::ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: orchard_tree_size,
                // Fabricated-chain test helper: no ironwood notes in these synthetic blocks.
                ironwood_commitment_tree_size: 0,
            }),
        }
    }

    /// One fabricated block in the cache the scan reads from - exactly what `download_blocks`
    /// produces from a one-block upstream stream.
    fn cached_block(
        height: u32,
        hash: [u8; 32],
        prev: [u8; 32],
        cmx: [u8; 32],
        orchard_tree_size: u32,
    ) -> MemBlockCache {
        let mut cache = MemBlockCache::new();
        cache.push(
            BlockHeight::from_u32(height),
            compact_block(height, hash, prev, cmx, orchard_tree_size).encode_to_vec(),
        );
        cache
    }

    /// One batch of consecutive fabricated blocks `from..=to`, hashed with `hash_tag` and
    /// carrying commitments tagged `cmx_tag`, linking from `prev`.
    fn cached_chain(
        hash_tag: u8,
        cmx_tag: u8,
        from: u32,
        to: u32,
        mut prev: [u8; 32],
    ) -> MemBlockCache {
        let mut cache = MemBlockCache::new();
        for h in from..=to {
            let hash = fake_hash(hash_tag, h);
            cache.push(
                BlockHeight::from_u32(h),
                compact_block(h, hash, prev, cmx_bytes(cmx_tag, h), h).encode_to_vec(),
            );
            prev = hash;
        }
        cache
    }

    fn chain_state(height: u32, hash: [u8; 32], orchard: &OrchardFrontier) -> ChainState {
        // The pinned scan-model `ChainState::new` takes a 5th ironwood final-tree frontier (ironwood
        // notes are tracked in a separate shardtree). Empty: the fabricated reorg-test chain has no
        // ironwood notes.
        ChainState::new(
            BlockHeight::from_u32(height),
            BlockHash(hash),
            Frontier::empty(),
            orchard.clone(),
            Frontier::empty(),
        )
    }

    fn range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::Historic,
        )
    }

    fn max_scanned(db: &WriteDb) -> Option<u32> {
        db.block_max_scanned()
            .expect("block_max_scanned")
            .map(|m| u32::from(m.block_height()))
    }

    /// A wallet born at genesis with an empty prior chain state, so scanning can start at
    /// height 1 (mirrors the offline regtest lifecycle test), with chain A (`1..=blocks`, one
    /// Orchard commitment each) scanned a block at a time while tracking the growing tree
    /// frontier (the server-side tree state a real upstream would report for each prior
    /// block). Returns the wallet, the frontier after the whole chain, and the frontier after
    /// block 1 (the state a rewind to 1 resumes from).
    fn scanned_chain_a(
        wd: &std::path::Path,
        blocks: u32,
    ) -> (WriteDb, OrchardFrontier, OrchardFrontier) {
        let net = crate::network::regtest();
        let mut db_data = crate::wallet::open::init_dbs(net, wd).expect("init dbs");

        let genesis = fake_hash(0xAA, 0);
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash(genesis)),
            None,
        );
        db_data
            .create_account("t", &SecretVec::new(vec![1u8; 64]), &birthday, None)
            .expect("create account");
        db_data
            .update_chain_tip(BlockHeight::from_u32(blocks))
            .expect("set tip");

        let mut frontier = OrchardFrontier::empty();
        let mut frontier_at_1 = OrchardFrontier::empty();
        let mut prev = genesis;
        for h in 1..=blocks {
            let from = chain_state(h - 1, prev, &frontier);
            let hash = fake_hash(0xA1, h);
            let cmx = cmx_bytes(0x0A, h);
            scan_blocks(
                &net,
                &cached_block(h, hash, prev, cmx, h),
                &mut db_data,
                &from,
                &range(h, h + 1),
                REORG_BASE_MARGIN,
            )
            .expect("scan chain A block");
            assert!(frontier.append(MerkleHashOrchard::from_cmx(
                &ExtractedNoteCommitment::from_bytes(&cmx).unwrap()
            )));
            if h == 1 {
                frontier_at_1 = frontier.clone();
            }
            prev = hash;
        }
        assert_eq!(max_scanned(&db_data), Some(blocks), "chain A fully scanned");
        (db_data, frontier, frontier_at_1)
    }

    /// The rewind margin decides how far one reorg round trip walks back, and doubling it is
    /// what turns a deep rollback from a linear walk into a logarithmic one. Drive the same
    /// continuity-error branch with two margins and require the wallet to land where each says.
    ///
    /// This is the arithmetic behind a real incident: a node rolled back 1,835 blocks, and the
    /// wallet - which only ever sees a fork one block at a time, at its own tip - took 62 rounds
    /// of ten blocks each, about ten minutes, to walk back to it.
    #[test]
    fn rewind_margin_sets_how_far_one_reorg_round_trip_walks_back() {
        for (margin, expected_tip) in [(REORG_BASE_MARGIN, 51u32), (40, 21)] {
            let net = crate::network::regtest();
            let dir = tempfile::tempdir().unwrap();
            // A chain long enough that a 40-block rewind still lands well above the birthday,
            // so what is under test is the margin rather than the wallet running out of
            // rewindable history.
            let (mut db_data, frontier, _) = scanned_chain_a(dir.path(), 60);

            // Block 61 arrives claiming a different block 60 as its parent.
            let alien_60 = fake_hash(0xB1, 60);
            let outcome = scan_blocks(
                &net,
                &cached_block(61, fake_hash(0xB1, 61), alien_60, cmx_bytes(0x0B, 61), 61),
                &mut db_data,
                &chain_state(60, alien_60, &frontier),
                &range(61, 62),
                margin,
            )
            .expect("continuity error is handled, not propagated");

            assert!(
                outcome.reorged,
                "margin {margin}: the reorg must be reported"
            );
            assert_eq!(
                max_scanned(&db_data),
                Some(expected_tip),
                "margin {margin}: one round trip rewinds to (conflict height - margin)"
            );
        }
    }

    /// The margin grows only while reorgs keep coming, and snaps back on the first clean batch,
    /// so a wallet that is keeping up never carries a widened one.
    #[test]
    fn reorg_margin_doubles_while_reorging_and_resets_when_clean() {
        let mut margin = REORG_BASE_MARGIN;
        let mut seen = vec![margin];
        for _ in 0..7 {
            margin = next_reorg_margin(margin, true);
            seen.push(margin);
        }
        assert_eq!(seen, vec![10, 20, 40, 80, 160, 320, 640, 1280]);
        // Eight rounds cover the 1,835-block rollback that motivated this, against the 62 the
        // fixed margin took. (Seven would not: they reach 1,270.)
        assert!(
            seen.iter().sum::<u32>() >= 1_835,
            "doubling must reach a deep rollback in a handful of rounds: {seen:?}"
        );
        assert!(
            seen[..seen.len() - 1].iter().sum::<u32>() < 1_835,
            "and eight is the number of rounds it takes, not fewer: {seen:?}"
        );

        assert_eq!(
            next_reorg_margin(1280, false),
            REORG_BASE_MARGIN,
            "a clean batch resets the margin"
        );
        assert_eq!(
            next_reorg_margin(REORG_BASE_MARGIN, false),
            REORG_BASE_MARGIN
        );
        // And it is bounded: a wallet stuck reorging cannot grow the margin without limit.
        let mut m = REORG_BASE_MARGIN;
        for _ in 0..64 {
            m = next_reorg_margin(m, true);
        }
        assert_eq!(m, REORG_MAX_MARGIN);
    }

    /// Drive `scan_blocks`' continuity-error branch - the only code in zecd that handles
    /// reorgs - end to end and offline: scan a fabricated chain, present a block whose
    /// `prev_hash` contradicts the wallet's stored tip (what a post-reorg upstream serves),
    /// verify the rewind, then that the replacement chain - served as one batch, the way the
    /// sync loop would download it - scans cleanly past the old tip.
    ///
    /// The batch that hit the reorg is simply dropped: it only ever lived in memory, so there
    /// is no cache to truncate and no stale block file to delete. (The file-cache era had three
    /// more tests here for exactly that bookkeeping; the memory cache has none to get wrong.)
    #[test]
    fn reorg_rewinds_the_wallet_and_the_replacement_chain_scans() {
        let net = crate::network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let (mut db_data, _, frontier_at_1) = scanned_chain_a(dir.path(), 10);

        // The reorg: the upstream now serves a block 11 whose prev_hash is a *different*
        // block 10 (the replacement fork's), contradicting the wallet's stored chain-A tip.
        let alien_10 = fake_hash(0xB1, 10);
        let outcome = scan_blocks(
            &net,
            &cached_block(11, fake_hash(0xB1, 11), alien_10, cmx_bytes(0x0B, 11), 11),
            &mut db_data,
            // The continuity check fires before any tree work, so the (unknowable) post-
            // reorg server tree state never comes into play; empty stands in for it.
            &ChainState::empty(BlockHeight::from_u32(10), BlockHash(alien_10)),
            &range(11, 12),
            REORG_BASE_MARGIN,
        )
        .expect("the continuity error is handled, not propagated");
        assert!(
            outcome.reorged,
            "a continuity break is reported as a reorg (rewound, range not applied)"
        );
        assert!(
            outcome.ranges_changed,
            "a rewind reports that the scan ranges changed"
        );

        // The rewind: continuity broke at 11, so the wallet rewound to 11 - 10 = 1.
        assert_eq!(
            max_scanned(&db_data),
            Some(1),
            "wallet truncated to the rewind height"
        );

        // The replacement chain B (2..=12, linking from the surviving block 1) scans
        // cleanly: the wallet recovers past its old tip with no manual intervention.
        db_data
            .update_chain_tip(BlockHeight::from_u32(12))
            .expect("advance tip");
        scan_blocks(
            &net,
            &cached_chain(0xB1, 0x0B, 2, 12, fake_hash(0xA1, 1)),
            &mut db_data,
            &chain_state(1, fake_hash(0xA1, 1), &frontier_at_1),
            &range(2, 13),
            REORG_BASE_MARGIN,
        )
        .expect("scan the replacement chain");
        assert_eq!(
            max_scanned(&db_data),
            Some(12),
            "recovered past the old tip"
        );
    }

    /// Scan a short chain so the standard 10-block rewind margin lands below the wallet's
    /// first scanned block, then exercise `perform_rewind`'s shallow retry directly.
    fn short_chain_wallet(wd: &std::path::Path, blocks: u32) -> WriteDb {
        scanned_chain_a(wd, blocks).0
    }

    /// A reorg within 10 blocks of the wallet's entire scanned history: the requested rewind
    /// (`at_height - 10`, floored at 0) has no checkpoint at or below it, so a bare
    /// `truncate_to_height` fails with `RequestedRewindInvalid` on every retry. The shallow
    /// retry (truncate at `at_height - 2`) must rewind to the highest checkpointed block
    /// *strictly below* the known-stale block at `at_height - 1` - here 4, not 5 - so the
    /// conflicting block is removed and retries make progress.
    #[test]
    fn rewind_falls_back_to_shallow_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let mut db_data = short_chain_wallet(dir.path(), 5);

        let rewound = perform_rewind(
            &mut db_data,
            BlockHeight::from_u32(6),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(0),
        )
        .expect("shallow fallback rewinds");
        assert_eq!(
            u32::from(rewound),
            4,
            "rewound below the stale block at at_height - 1"
        );
        assert_eq!(
            max_scanned(&db_data),
            Some(4),
            "wallet truncated to the fallback target"
        );
    }

    /// A reorg deeper than the wallet's rewindable history (only block 1 is scanned and the
    /// conflict is right above it) has no valid fallback: the error must say so clearly
    /// instead of surfacing a bare `RequestedRewindInvalid`.
    #[test]
    fn rewind_reports_unrecoverable_reorg() {
        let dir = tempfile::tempdir().unwrap();
        let mut db_data = short_chain_wallet(dir.path(), 1);

        let err = perform_rewind(
            &mut db_data,
            BlockHeight::from_u32(2),
            BlockHeight::from_u32(0),
            BlockHeight::from_u32(0),
        )
        .expect_err("nothing below the conflict to rewind to");
        // Typed, not just worded: the actor halts this wallet's sync on exactly this type, and
        // retries every other failure. A bare `anyhow!` here would be retried forever.
        let unrecoverable = err
            .downcast_ref::<UnrecoverableReorg>()
            .expect("the terminal class must be recoverable by type, not by message text");
        assert_eq!(u32::from(unrecoverable.at_height), 2);
        assert!(
            err.to_string().contains("unrecoverable reorg"),
            "unexpected error: {err:#}"
        );
        assert_eq!(max_scanned(&db_data), Some(1), "wallet state untouched");
    }

    /// The storage layer's `safe_rewind_height` is *not* a target to retry blindly: it can name
    /// the very height that was just refused. Truncating a 1-block wallet to 0 does exactly that
    /// (`RequestedRewindInvalid { safe_rewind_height: Some(0), requested_height: 0 }`), so a
    /// candidate list that fed it back in would re-issue the identical failing call - the same
    /// shape of infinite retry this whole change removes. Pin the upstream behaviour that makes
    /// the guard necessary, so a bump that changes it shows up here.
    #[test]
    fn safe_rewind_height_can_name_the_refused_height() {
        let dir = tempfile::tempdir().unwrap();
        let mut db_data = short_chain_wallet(dir.path(), 1);

        match db_data.truncate_to_height(BlockHeight::from_u32(0)) {
            Err(SqliteClientError::RequestedRewindInvalid {
                safe_rewind_height,
                requested_height,
            }) => {
                assert_eq!(u32::from(requested_height), 0);
                assert_eq!(
                    safe_rewind_height.map(u32::from),
                    Some(0),
                    "upstream named a safe height other than the refused one; \
                     `perform_rewind`'s `< requested` filter may now be over-cautious"
                );
            }
            other => panic!("expected the truncation to 0 to be refused, got {other:?}"),
        }
    }

    fn tip_range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::ChainTip,
        )
    }

    /// The guess is what the next batch will select, worked out from the ranges as they are
    /// *before* the current one is scanned - which is what lets the fetch start early enough
    /// to overlap the scan. A guess is only useful if it is exactly right, since a mismatch is
    /// discarded, so it must chunk the remainder the way `sync_one_batch` chunks a range.
    #[test]
    fn next_range_guess_is_the_next_batch_selection() {
        let first = tip_range(100, 100_000);
        let scanning = tip_range(100, 25_100);
        let guess = next_range_guess(std::slice::from_ref(&first), &scanning, 25_000)
            .expect("more range remains");
        assert_eq!(guess, tip_range(25_100, 50_100));

        // The last chunk of a range is shorter than a full batch, and is guessed whole.
        let first = tip_range(100, 30_000);
        let guess = next_range_guess(std::slice::from_ref(&first), &scanning, 25_000)
            .expect("a short tail remains");
        assert_eq!(guess, tip_range(25_100, 30_000));
    }

    /// Nothing to fetch ahead: no ranges, the current batch finishing the range in hand, or a
    /// pending `Verify` range (small, first, and what follows it depends on what it finds).
    #[test]
    fn no_guess_when_nothing_follows_the_current_batch() {
        let whole = tip_range(100, 1_100);
        assert!(next_range_guess(&[], &whole, 25_000).is_none());
        assert!(next_range_guess(std::slice::from_ref(&whole), &whole, 25_000).is_none());

        let verify = ScanRange::from_parts(
            BlockHeight::from_u32(100)..BlockHeight::from_u32(110),
            ScanPriority::Verify,
        );
        assert!(next_range_guess(std::slice::from_ref(&verify), &verify, 25_000).is_none());
    }

    /// The load-shed retry resumes one past the last block actually written, so a reconnect
    /// costs only the blocks the killed connection never delivered. With nothing written yet
    /// it re-requests the same start.
    #[test]
    fn a_load_shed_resumes_past_the_last_block_written() {
        let mut stalled = 0u32;
        assert_eq!(
            plan_load_shed_resume(
                true,
                Some(BlockHeight::from_u32(1_234)),
                BlockHeight::from_u32(1_000),
                &mut stalled,
            ),
            Some(BlockHeight::from_u32(1_235)),
        );
        assert_eq!(stalled, 0, "progress resets the stall count");

        // Nothing written at all: retry the same height.
        assert_eq!(
            plan_load_shed_resume(false, None, BlockHeight::from_u32(1_000), &mut stalled),
            Some(BlockHeight::from_u32(1_000)),
        );
    }

    /// A download that keeps advancing keeps resuming however many load sheds it takes; only
    /// a range that cannot advance at all gives up, and only after a bounded number of tries.
    /// Without the reset, a long first sync on a bad-enough connection would fail the batch
    /// after three sheds even while making steady progress.
    #[test]
    fn only_a_download_that_stops_advancing_gives_up() {
        let mut stalled = 0u32;
        // Twenty sheds, each after real progress: never gives up.
        let mut height = 1_000u32;
        for _ in 0..20 {
            height += 500;
            assert!(
                plan_load_shed_resume(
                    true,
                    Some(BlockHeight::from_u32(height)),
                    BlockHeight::from_u32(height),
                    &mut stalled,
                )
                .is_some(),
                "progress must keep the retry alive"
            );
        }

        // Now the range stops advancing: tolerated MAX times, then given up on.
        let stuck = BlockHeight::from_u32(height + 1);
        for attempt in 1..=MAX_STALLED_STREAM_RESTARTS {
            assert!(
                plan_load_shed_resume(false, Some(height.into()), stuck, &mut stalled).is_some(),
                "zero-progress attempt {attempt} is still within budget"
            );
        }
        assert_eq!(
            plan_load_shed_resume(false, Some(height.into()), stuck, &mut stalled),
            None,
            "past the budget the error surfaces instead of looping"
        );

        // One block of progress buys the full budget back.
        assert!(plan_load_shed_resume(true, Some(stuck), stuck, &mut stalled).is_some());
        assert_eq!(stalled, 0);
    }
}
