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

use std::collections::HashSet;
use std::path::Path;

use anyhow::anyhow;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};
use zcash_client_backend::data_api::{
    chain::{
        error::Error as ChainError, scan_cached_blocks, BlockSource, ChainState, CommitmentTreeRoot,
    },
    scanning::{ScanPriority, ScanRange},
    WalletCommitmentTrees, WalletRead, WalletWrite,
};
use zcash_client_backend::wallet::WalletTransparentOutput;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::{chain::BlockMeta, FsBlockDb, FsBlockDbError};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::{ShieldedProtocol, TxId};
use zcash_transparent::address::TransparentAddress;

use crate::chain::ChainSource;
use crate::network::ZNetwork;
use crate::wallet::open::{block_path, WriteDb};

const BATCH_SIZE: u32 = 10_000;

/// Download Sapling + Orchard note-commitment subtree roots and hand them to the wallet.
/// Run once at startup (and cheaply repeatable).
pub async fn update_subtree_roots<C: ChainSource>(
    client: &mut C,
    db_data: &mut WriteDb,
) -> anyhow::Result<()> {
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .subtree_roots(ShieldedProtocol::Sapling)
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
        .subtree_roots(ShieldedProtocol::Orchard)
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

    Ok(())
}

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
) -> Option<WalletTransparentOutput> {
    use zcash_transparent::address::Script;
    use zcash_transparent::bundle::{OutPoint, TxOut};
    let value = Zatoshis::from_u64(value_zat).ok()?;
    let outpoint = OutPoint::new(*txid.as_ref(), index);
    let txout = TxOut::new(value, Script(zcash_script::script::Code(script)));
    let output =
        WalletTransparentOutput::from_parts(outpoint, txout, height.map(BlockHeight::from_u32))?;
    addresses
        .contains(output.recipient_address())
        .then_some(output)
}

async fn download_blocks<C: ChainSource>(
    name: &str,
    client: &mut C,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    scan_range: &ScanRange,
    transparent: Option<&HashSet<TransparentAddress>>,
) -> anyhow::Result<(Vec<BlockMeta>, Vec<WalletTransparentOutput>)> {
    info!("[{name}] Fetching {scan_range}");
    let mut stream = client
        .compact_block_range(
            scan_range.block_range().start,
            scan_range.block_range().end - 1,
            transparent.is_some(),
        )
        .await?;

    let mut block_meta = vec![];
    let mut received = vec![];
    while let Some((block, t_outs)) = stream.next().await? {
        let (sapling_outputs_count, orchard_actions_count) = block
            .vtx
            .iter()
            .map(|tx| (tx.outputs.len() as u32, tx.actions.len() as u32))
            .fold((0, 0), |(acc_s, acc_o), (s, o)| (acc_s + s, acc_o + o));

        let meta = BlockMeta {
            height: block.height(),
            block_hash: block.hash(),
            block_time: block.time,
            sapling_outputs_count,
            orchard_actions_count,
        };

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
                    received.push(output);
                }
            }
        }

        let encoded = block.encode_to_vec();
        let mut block_file = File::create(block_path(wallet_dir, &meta)).await?;
        block_file.write_all(&encoded).await?;
        block_meta.push(meta);
    }

    db_cache
        .write_block_metadata(&block_meta)
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok((block_meta, received))
}

async fn download_chain_state<C: ChainSource>(
    client: &mut C,
    block_height: BlockHeight,
) -> anyhow::Result<ChainState> {
    let tree_state = client.tree_state(block_height).await?;
    Ok(tree_state.to_chain_state()?)
}

/// Remove a just-scanned batch's cached compact-block files *and* their `compactblocks_meta`
/// rows, keeping the on-disk cache and the metadata table consistent.
///
/// Dropping only the files (as this used to) left the metadata rows behind for every scanned
/// height forever: on a long-lived node `compactblocks_meta` then grew without bound, and -
/// worse - a later reorg's `with_blocks` pass would try to open those now-fileless rows and
/// fail with `NotFound` before the rewind's `truncate_to_height` could run, so the intended
/// in-place reorg recovery never completed. Because sync processes one batch per call
/// (download → scan → delete before the next), truncating to just below the batch's lowest
/// height removes exactly this batch's rows, so the table never accumulates.
fn delete_cached_blocks(
    name: &str,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    block_meta: Vec<BlockMeta>,
) {
    let lowest = block_meta.iter().map(|m| m.height).min();
    for meta in &block_meta {
        if let Err(e) = std::fs::remove_file(block_path(wallet_dir, meta)) {
            warn!("[{name}] Failed to remove cached block {:?}: {}", meta, e);
        }
    }
    if let Some(lowest) = lowest {
        let truncate_to = BlockHeight::from(u32::from(lowest).saturating_sub(1));
        if let Err(e) = db_cache.truncate_to_height(truncate_to) {
            warn!("[{name}] Failed to truncate block cache metadata to {truncate_to}: {e:?}");
        }
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
    name: &str,
    db_data: &mut WriteDb,
    at_height: BlockHeight,
    requested: BlockHeight,
) -> anyhow::Result<BlockHeight> {
    match db_data.truncate_to_height(requested) {
        Ok(h) => Ok(h),
        Err(SqliteClientError::RequestedRewindInvalid { .. }) => {
            let bound = BlockHeight::from(u32::from(at_height).saturating_sub(2));
            match db_data.truncate_to_height(bound) {
                Ok(h) => {
                    info!(
                        "[{name}] Shallow rewind to {h} (no valid target at or below {requested})"
                    );
                    Ok(h)
                }
                // No scanned block below the conflict can be rewound to: the reorg is
                // deeper than the wallet's rewindable history. Recovering needs a
                // from-birthday resync.
                Err(SqliteClientError::RequestedRewindInvalid { .. }) => Err(anyhow!(
                    "unrecoverable reorg at {at_height}: no note-commitment-tree checkpoint \
                     with a scanned block exists below the conflict (requested rewind to \
                     {requested}); restore the wallet from its mnemonic into a fresh \
                     directory (`zecd init --restore`) to resync from the wallet birthday"
                )),
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
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

/// Scan a downloaded range; handle continuity (reorg) errors by rewinding. See [`ScanOutcome`].
fn scan_blocks(
    name: &str,
    params: &ZNetwork,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
) -> anyhow::Result<ScanOutcome> {
    info!("[{name}] Scanning {scan_range}");
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            let requested = err.at_height().saturating_sub(10);
            info!(
                "[{name}] Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                requested
            );
            // NB: truncation requires a note-commitment-tree checkpoint, and per-block
            // checkpoints exist only for scanned blocks that carried shielded outputs
            // (virtually all real blocks). `perform_rewind` falls back to the nearest
            // valid checkpoint when the requested height has none; the cache is then
            // truncated to the height actually rewound to.
            let rewind_height = perform_rewind(name, db_data, err.at_height(), requested)?;
            // Delete the now-stale cached block files above the rewind height. A metadata row
            // whose backing file is already gone (rows left behind by an older zecd that removed
            // files but not their `compactblocks_meta` rows) must not abort this: `with_blocks`
            // opens each row's file *before* handing it to the closure, so a `NotFound` there
            // would propagate and skip the `truncate_to_height` below - leaving the metadata
            // un-truncated and the in-place reorg recovery broken (the node could then only
            // recover by dropping the client and redownloading). Treat a missing file as
            // already-cleaned and fall through to the truncate, which drops every stale row in a
            // single statement regardless of how far `with_blocks` got.
            let cleanup = db_cache.with_blocks(Some(rewind_height + 1), None, |block| {
                let meta = BlockMeta {
                    height: block.height(),
                    block_hash: block.hash(),
                    block_time: block.time,
                    sapling_outputs_count: 0,
                    orchard_actions_count: 0,
                };
                match std::fs::remove_file(block_path(wallet_dir, &meta)) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(ChainError::<(), _>::BlockSource(FsBlockDbError::Fs(e))),
                }
            });
            match cleanup {
                Ok(()) => {}
                // The metadata rows above the rewind height were already removed (per-batch
                // cleanup keeps files and rows consistent), so `with_blocks` can't find its
                // `rewind_height + 1` starting row. Nothing left to delete on disk; the
                // in-flight batch's own files are removed by `delete_cached_blocks` back in
                // `sync_one_batch`. Fall through to truncate any remaining stale rows.
                Err(ChainError::BlockSource(FsBlockDbError::CacheMiss(_))) => {}
                // A metadata row whose backing file is already gone (rows left behind by an
                // older zecd that removed files but not their `compactblocks_meta` rows). Treat
                // it as already-cleaned; the truncate below drops the stale row.
                Err(ChainError::BlockSource(FsBlockDbError::Fs(e)))
                    if e.kind() == std::io::ErrorKind::NotFound =>
                {
                    warn!(
                        "[{name}] Stale block-cache metadata row had no backing file during \
                         reorg cleanup; truncating it"
                    );
                }
                Err(e) => return Err(anyhow!("{:?}", e)),
            }
            db_cache
                .truncate_to_height(rewind_height)
                .map_err(|e| anyhow!("{:?}", e))?;
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
        Err(e) => Err(anyhow!("{:?}", e)),
    }
}

/// Outcome of one sync batch: whether a batch was scanned (so the caller should call again), and
/// how many transparent receives were recorded from the block scan (so the actor can refresh its
/// exposed-address set - a recorded receive may have extended the transparent gap).
pub struct BatchOutcome {
    pub worked: bool,
    pub transparent_recorded: usize,
}

/// Process at most one batch of work. `worked` is `true` if a batch was scanned (caller should
/// call again), `false` if there are no pending scan ranges (wallet is caught up).
///
/// `transparent` is the wallet's exposed transparent address set when transparent receiving is
/// enabled (`None` for shielded-only wallets, which skips transparent extraction entirely). When
/// present, each scanned block's transparent outputs are matched against it and recorded as
/// receives via `put_received_transparent_utxo` after the shielded scan succeeds.
pub async fn sync_one_batch<C: ChainSource>(
    name: &str,
    client: &mut C,
    params: &ZNetwork,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
    transparent: Option<&HashSet<TransparentAddress>>,
) -> anyhow::Result<BatchOutcome> {
    let scan_ranges = db_data.suggest_scan_ranges()?;
    tracing::debug!(
        "[{name}] suggest_scan_ranges -> {} range(s): {:?}",
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
            transparent_recorded: 0,
        });
    };

    // A `Verify` range is always returned first and is small; scan it whole. Otherwise scan
    // the first BATCH_SIZE-block chunk of the highest-priority range.
    let scan_range = if first.priority() == ScanPriority::Verify {
        first.clone()
    } else {
        match first.split_at(first.block_range().start + BATCH_SIZE) {
            Some((cur, _next)) => cur,
            None => first.clone(),
        }
    };

    let (block_meta, received) =
        download_blocks(name, client, wallet_dir, db_cache, &scan_range, transparent).await?;

    // Fetch the prior block's chain state and scan. Anything that fails here must still clean up
    // the just-downloaded cache files, so the result is captured and the delete runs regardless.
    let result = async {
        // Never request the tree state below height 1: lightwalletd treats BlockId height 0 as
        // "unspecified" and rejects it, and there's no pre-genesis tree state. On a genesis-
        // adjacent range (fresh regtest) `start - 1` would be 0; clamp to 1 (mirrors init.rs).
        let start = u32::from(scan_range.block_range().start);
        let prior_height = BlockHeight::from(start.saturating_sub(1).max(1));
        let chain_state = download_chain_state(client, prior_height).await?;

        // `scan_cached_blocks` is CPU-bound; keep the async runtime healthy.
        let outcome = tokio::task::block_in_place(|| {
            scan_blocks(
                name,
                params,
                wallet_dir,
                db_cache,
                db_data,
                &chain_state,
                &scan_range,
            )
        })?;
        Ok::<ScanOutcome, anyhow::Error>(outcome)
    }
    .await;

    // Remove the downloaded compact blocks (files and their metadata rows) whether the scan
    // succeeded or failed, so a transient error (or a reorg-shifted range) cannot strand cache
    // files on disk or leave stale `compactblocks_meta` rows behind.
    delete_cached_blocks(name, wallet_dir, db_cache, block_meta);
    let outcome = result?;

    // Record the transparent receives matched during download - but only when the range was
    // actually applied. On a reorg the wallet rewound instead of scanning these blocks, so the
    // outputs belong to the abandoned fork and must be dropped (the replacement chain's blocks
    // re-surface the real receives on the next pass). `put_received_transparent_utxo` is
    // idempotent, so re-recording across overlapping passes is harmless.
    let mut transparent_recorded = 0;
    if !outcome.reorged {
        for output in &received {
            match db_data.put_received_transparent_utxo(output) {
                Ok(_) => transparent_recorded += 1,
                Err(e) => warn!(
                    "[{name}] recording transparent receive {}:{} failed: {e}",
                    output.outpoint().txid(),
                    output.outpoint().n(),
                ),
            }
        }
        if transparent_recorded > 0 {
            info!(
                "[{name}] recorded {transparent_recorded} transparent receive(s) from block scan"
            );
        }
    }

    Ok(BatchOutcome {
        worked: true,
        transparent_recorded,
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
    /// to), write its file into the cache directory, and record its metadata in the cache
    /// DB - exactly what `download_blocks` does with a lightwalletd stream.
    fn write_block(
        wallet_dir: &Path,
        db_cache: &mut FsBlockDb,
        height: u32,
        hash: [u8; 32],
        prev: [u8; 32],
        cmx: [u8; 32],
        orchard_tree_size: u32,
    ) -> BlockMeta {
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
        let cb = pb::CompactBlock {
            proto_version: 0,
            height: u64::from(height),
            hash: hash.to_vec(),
            prev_hash: prev.to_vec(),
            time: 1_700_000_000 + height,
            header: vec![],
            vtx: vec![tx],
            chain_metadata: Some(pb::ChainMetadata {
                sapling_commitment_tree_size: 0,
                orchard_commitment_tree_size: orchard_tree_size,
            }),
        };
        let meta = BlockMeta {
            height: BlockHeight::from_u32(height),
            block_hash: BlockHash(hash),
            block_time: cb.time,
            sapling_outputs_count: 0,
            orchard_actions_count: 1,
        };
        std::fs::write(block_path(wallet_dir, &meta), cb.encode_to_vec())
            .expect("write compact block file");
        db_cache
            .write_block_metadata(&[meta])
            .expect("record block metadata");
        meta
    }

    fn chain_state(height: u32, hash: [u8; 32], orchard: &OrchardFrontier) -> ChainState {
        ChainState::new(
            BlockHeight::from_u32(height),
            BlockHash(hash),
            Frontier::empty(),
            orchard.clone(),
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

    /// Drive `scan_blocks`\' continuity-error branch - the only code in zecd that handles
    /// reorgs - end to end and offline: scan a fabricated chain, present a block whose
    /// `prev_hash` contradicts the wallet\'s stored tip (what a post-reorg lightwalletd
    /// serves), and verify the rewind (wallet truncated, cache truncated, stale block files
    /// deleted), then that the replacement chain scans cleanly past the old tip.
    #[test]
    fn reorg_rewinds_wallet_cache_and_files() {
        let net = crate::network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let wd = dir.path();
        let mut db_data = crate::wallet::open::init_dbs(net, wd).expect("init dbs");
        let mut db_cache = crate::wallet::open::open_fsblockdb(wd).expect("open cache");
        std::fs::create_dir_all(wd.join("blocks")).expect("blocks dir");

        // An account born at genesis with an empty prior chain state, so scanning can start
        // at height 1 (mirrors the offline regtest lifecycle test).
        let genesis = fake_hash(0xAA, 0);
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash(genesis)),
            None,
        );
        db_data
            .create_account("t", &SecretVec::new(vec![1u8; 64]), &birthday, None)
            .expect("create account");
        db_data
            .update_chain_tip(BlockHeight::from_u32(10))
            .expect("set tip");

        // Chain A: blocks 1..=10, one Orchard commitment each, scanned a block at a time
        // while tracking the growing tree frontier (the server-side tree state a real
        // lightwalletd would report for each prior block).
        let mut frontier = OrchardFrontier::empty();
        let mut frontier_at_1 = OrchardFrontier::empty();
        let mut prev = genesis;
        let mut metas_a = Vec::new();
        for h in 1..=10u32 {
            let from = chain_state(h - 1, prev, &frontier);
            let hash = fake_hash(0xA1, h);
            let cmx = cmx_bytes(0x0A, h);
            metas_a.push(write_block(wd, &mut db_cache, h, hash, prev, cmx, h));
            scan_blocks(
                "test",
                &net,
                wd,
                &mut db_cache,
                &mut db_data,
                &from,
                &range(h, h + 1),
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
        assert_eq!(max_scanned(&db_data), Some(10), "chain A fully scanned");

        // The reorg: lightwalletd now serves a block 11 whose prev_hash is a *different*
        // block 10 (the replacement fork\'s), contradicting the wallet\'s stored chain-A tip.
        let alien_10 = fake_hash(0xB1, 10);
        write_block(
            wd,
            &mut db_cache,
            11,
            fake_hash(0xB1, 11),
            alien_10,
            cmx_bytes(0x0B, 11),
            11,
        );
        let outcome = scan_blocks(
            "test",
            &net,
            wd,
            &mut db_cache,
            &mut db_data,
            // The continuity check fires before any tree work, so the (unknowable) post-
            // reorg server tree state never comes into play; empty stands in for it.
            &ChainState::empty(BlockHeight::from_u32(10), BlockHash(alien_10)),
            &range(11, 12),
        )
        .expect("the continuity error is handled, not propagated");
        assert!(
            outcome.reorged,
            "a continuity break is reported as a reorg (rewound, range not applied)"
        );

        // The rewind: continuity broke at 11, so the wallet rewound to 11 - 10 = 1...
        assert_eq!(
            max_scanned(&db_data),
            Some(1),
            "wallet truncated to the rewind height"
        );
        // ...the block cache is truncated to match...
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached height"),
            Some(BlockHeight::from_u32(1)),
            "cache truncated to the rewind height"
        );
        // ...and the now-stale cached block files above it are deleted from disk.
        assert!(
            block_path(wd, &metas_a[0]).exists(),
            "block 1\'s file survives"
        );
        for m in &metas_a[1..] {
            assert!(
                !block_path(wd, m).exists(),
                "stale chain-A file above the rewind height was deleted: {m:?}"
            );
        }

        // The replacement chain B (2..=12, linking from the surviving block 1) scans
        // cleanly: the wallet recovers past its old tip with no manual intervention.
        let mut prev = fake_hash(0xA1, 1);
        for h in 2..=12u32 {
            let hash = fake_hash(0xB1, h);
            write_block(wd, &mut db_cache, h, hash, prev, cmx_bytes(0x0B, h), h);
            prev = hash;
        }
        db_data
            .update_chain_tip(BlockHeight::from_u32(12))
            .expect("advance tip");
        scan_blocks(
            "test",
            &net,
            wd,
            &mut db_cache,
            &mut db_data,
            &chain_state(1, fake_hash(0xA1, 1), &frontier_at_1),
            &range(2, 13),
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
    fn short_chain_wallet(wd: &Path, blocks: u32) -> WriteDb {
        let net = crate::network::regtest();
        let mut db_data = crate::wallet::open::init_dbs(net, wd).expect("init dbs");
        let mut db_cache = crate::wallet::open::open_fsblockdb(wd).expect("open cache");
        std::fs::create_dir_all(wd.join("blocks")).expect("blocks dir");

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
        let mut prev = genesis;
        for h in 1..=blocks {
            let from = chain_state(h - 1, prev, &frontier);
            let hash = fake_hash(0xA1, h);
            let cmx = cmx_bytes(0x0A, h);
            write_block(wd, &mut db_cache, h, hash, prev, cmx, h);
            scan_blocks(
                "test",
                &net,
                wd,
                &mut db_cache,
                &mut db_data,
                &from,
                &range(h, h + 1),
            )
            .expect("scan block");
            assert!(frontier.append(MerkleHashOrchard::from_cmx(
                &ExtractedNoteCommitment::from_bytes(&cmx).unwrap()
            )));
            prev = hash;
        }
        assert_eq!(max_scanned(&db_data), Some(blocks));
        db_data
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
        let wd = dir.path();
        let mut db_data = short_chain_wallet(wd, 5);

        let rewound = perform_rewind(
            "test",
            &mut db_data,
            BlockHeight::from_u32(6),
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
        let wd = dir.path();
        let mut db_data = short_chain_wallet(wd, 1);

        let err = perform_rewind(
            "test",
            &mut db_data,
            BlockHeight::from_u32(2),
            BlockHeight::from_u32(0),
        )
        .expect_err("nothing below the conflict to rewind to");
        assert!(
            err.to_string().contains("unrecoverable reorg"),
            "unexpected error: {err:#}"
        );
        assert_eq!(max_scanned(&db_data), Some(1), "wallet state untouched");
    }

    /// `delete_cached_blocks` must drop the batch's `compactblocks_meta` rows along with the
    /// files. Dropping only the files (the pre-fix behaviour) left a metadata row for every
    /// scanned height behind forever, so a caught-up node's cache metadata grew without bound
    /// (finding 3.4).
    #[test]
    fn delete_cached_blocks_removes_metadata_rows() {
        let dir = tempfile::tempdir().unwrap();
        let wd = dir.path();
        // `init_dbs` also runs `init_blockmeta_db`, creating the `compactblocks_meta` table.
        let _db_data =
            crate::wallet::open::init_dbs(crate::network::regtest(), wd).expect("init dbs");
        let mut db_cache = crate::wallet::open::open_fsblockdb(wd).expect("open cache");
        std::fs::create_dir_all(wd.join("blocks")).expect("blocks dir");

        // Simulate one downloaded+scanned batch: files on disk + matching metadata rows.
        let mut prev = fake_hash(0xAA, 0);
        let mut metas = Vec::new();
        for h in 1..=5u32 {
            let hash = fake_hash(0xA1, h);
            metas.push(write_block(
                wd,
                &mut db_cache,
                h,
                hash,
                prev,
                cmx_bytes(0x0A, h),
                h,
            ));
            prev = hash;
        }
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached"),
            Some(BlockHeight::from_u32(5)),
            "batch metadata present before cleanup"
        );

        delete_cached_blocks("test", wd, &mut db_cache, metas.clone());

        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached"),
            None,
            "metadata rows removed together with the files (no unbounded growth)"
        );
        for m in &metas {
            assert!(
                db_cache.find_block(m.height).expect("find_block").is_none(),
                "metadata row for {:?} gone",
                m.height
            );
            assert!(!block_path(wd, m).exists(), "file for {:?} gone", m.height);
        }
    }

    /// The finding's core regression: after normal multi-batch forward sync - where each
    /// batch's cache files (and now its metadata rows) are removed once scanned - a naturally
    /// occurring reorg must still recover *in place*. Before the fix the retained, now-fileless
    /// metadata rows made the rewind's `with_blocks` pass fail with `NotFound` before
    /// `truncate_to_height` ran, so recovery broke and `compactblocks_meta` was never truncated.
    #[test]
    fn reorg_recovers_after_per_batch_cache_deletion() {
        let net = crate::network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let wd = dir.path();
        let mut db_data = crate::wallet::open::init_dbs(net, wd).expect("init dbs");
        let mut db_cache = crate::wallet::open::open_fsblockdb(wd).expect("open cache");
        std::fs::create_dir_all(wd.join("blocks")).expect("blocks dir");

        let genesis = fake_hash(0xAA, 0);
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash(genesis)),
            None,
        );
        db_data
            .create_account("t", &SecretVec::new(vec![1u8; 64]), &birthday, None)
            .expect("create account");
        db_data
            .update_chain_tip(BlockHeight::from_u32(10))
            .expect("set tip");

        // Forward-sync chain A one block at a time, deleting each batch's cache after scanning
        // it (exactly what `sync_one_batch` does) so no block file survives on disk.
        let mut frontier = OrchardFrontier::empty();
        let mut frontier_at_1 = OrchardFrontier::empty();
        let mut prev = genesis;
        for h in 1..=10u32 {
            let from = chain_state(h - 1, prev, &frontier);
            let hash = fake_hash(0xA1, h);
            let cmx = cmx_bytes(0x0A, h);
            let meta = write_block(wd, &mut db_cache, h, hash, prev, cmx, h);
            scan_blocks(
                "test",
                &net,
                wd,
                &mut db_cache,
                &mut db_data,
                &from,
                &range(h, h + 1),
            )
            .expect("scan chain A block");
            delete_cached_blocks("test", wd, &mut db_cache, vec![meta]);
            assert!(frontier.append(MerkleHashOrchard::from_cmx(
                &ExtractedNoteCommitment::from_bytes(&cmx).unwrap()
            )));
            if h == 1 {
                frontier_at_1 = frontier.clone();
            }
            prev = hash;
        }
        assert_eq!(max_scanned(&db_data), Some(10), "chain A fully scanned");
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached"),
            None,
            "block cache metadata does not accumulate across batches"
        );

        // The reorg: a replacement block 11 whose prev_hash is a *different* block 10.
        let alien_10 = fake_hash(0xB1, 10);
        let meta_11 = write_block(
            wd,
            &mut db_cache,
            11,
            fake_hash(0xB1, 11),
            alien_10,
            cmx_bytes(0x0B, 11),
            11,
        );
        let worked = scan_blocks(
            "test",
            &net,
            wd,
            &mut db_cache,
            &mut db_data,
            &ChainState::empty(BlockHeight::from_u32(10), BlockHash(alien_10)),
            &range(11, 12),
        )
        .expect("reorg recovery must succeed even though prior batch files are gone");
        assert!(
            worked.ranges_changed,
            "a rewind reports that the scan ranges changed"
        );
        delete_cached_blocks("test", wd, &mut db_cache, vec![meta_11]);

        // Rewound to 11 - 10 = 1, and the cache metadata was truncated to match (empty, since
        // block 1's file+row were already removed by its own batch).
        assert_eq!(
            max_scanned(&db_data),
            Some(1),
            "wallet truncated to the rewind height"
        );
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached"),
            None,
            "cache metadata truncated, not left stale"
        );

        // The replacement chain B (2..=12, linking from the surviving block 1) scans cleanly.
        let mut prev = fake_hash(0xA1, 1);
        for h in 2..=12u32 {
            let hash = fake_hash(0xB1, h);
            write_block(wd, &mut db_cache, h, hash, prev, cmx_bytes(0x0B, h), h);
            prev = hash;
        }
        db_data
            .update_chain_tip(BlockHeight::from_u32(12))
            .expect("advance tip");
        scan_blocks(
            "test",
            &net,
            wd,
            &mut db_cache,
            &mut db_data,
            &chain_state(1, fake_hash(0xA1, 1), &frontier_at_1),
            &range(2, 13),
        )
        .expect("scan the replacement chain");
        assert_eq!(
            max_scanned(&db_data),
            Some(12),
            "recovered past the old tip"
        );
    }

    /// Backwards-compatibility for a node upgraded in place: an older zecd left
    /// `compactblocks_meta` rows whose backing files were already deleted. A reorg must still
    /// recover - the rewind treats the missing files as already-cleaned and truncates the stale
    /// rows - instead of failing on `NotFound` before `truncate_to_height` runs.
    #[test]
    fn reorg_tolerates_orphaned_metadata_rows() {
        let net = crate::network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let wd = dir.path();
        let mut db_data = crate::wallet::open::init_dbs(net, wd).expect("init dbs");
        let mut db_cache = crate::wallet::open::open_fsblockdb(wd).expect("open cache");
        std::fs::create_dir_all(wd.join("blocks")).expect("blocks dir");

        let genesis = fake_hash(0xAA, 0);
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash(genesis)),
            None,
        );
        db_data
            .create_account("t", &SecretVec::new(vec![1u8; 64]), &birthday, None)
            .expect("create account");
        db_data
            .update_chain_tip(BlockHeight::from_u32(10))
            .expect("set tip");

        // Scan chain A 1..=10, then simulate the OLD buggy cleanup: keep every metadata row but
        // delete the files for heights 2..=10 (the drift the finding is about).
        let mut frontier = OrchardFrontier::empty();
        let mut prev = genesis;
        let mut metas = Vec::new();
        for h in 1..=10u32 {
            let from = chain_state(h - 1, prev, &frontier);
            let hash = fake_hash(0xA1, h);
            let cmx = cmx_bytes(0x0A, h);
            metas.push(write_block(wd, &mut db_cache, h, hash, prev, cmx, h));
            scan_blocks(
                "test",
                &net,
                wd,
                &mut db_cache,
                &mut db_data,
                &from,
                &range(h, h + 1),
            )
            .expect("scan chain A block");
            assert!(frontier.append(MerkleHashOrchard::from_cmx(
                &ExtractedNoteCommitment::from_bytes(&cmx).unwrap()
            )));
            prev = hash;
        }
        for m in &metas[1..] {
            std::fs::remove_file(block_path(wd, m)).expect("remove stale cache file");
        }
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached"),
            Some(BlockHeight::from_u32(10)),
            "orphaned metadata rows retained, reproducing the drift"
        );

        // The reorg now drives the rewind over the orphaned rows: it must tolerate the missing
        // files and still truncate the metadata rather than erroring.
        let alien_10 = fake_hash(0xB1, 10);
        write_block(
            wd,
            &mut db_cache,
            11,
            fake_hash(0xB1, 11),
            alien_10,
            cmx_bytes(0x0B, 11),
            11,
        );
        scan_blocks(
            "test",
            &net,
            wd,
            &mut db_cache,
            &mut db_data,
            &ChainState::empty(BlockHeight::from_u32(10), BlockHash(alien_10)),
            &range(11, 12),
        )
        .expect("reorg recovery tolerates orphaned metadata rows");

        assert_eq!(
            max_scanned(&db_data),
            Some(1),
            "wallet truncated to the rewind height"
        );
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached"),
            Some(BlockHeight::from_u32(1)),
            "stale metadata truncated to the rewind height (no longer growing without bound)"
        );
    }
}
