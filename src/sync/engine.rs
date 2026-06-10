//! lightwalletd-backed block sync, ported from `zcash-devtool/src/commands/wallet/sync.rs`
//! and refactored to process one batch per call so the owning actor can interleave RPC
//! commands between batches. TUI and transparent-input handling are removed (Orchard-only).

use std::path::Path;

use anyhow::anyhow;
use futures_util::TryStreamExt;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tonic::transport::Channel;
use tracing::{info, warn};
use zcash_client_backend::data_api::{
    chain::{
        error::Error as ChainError, scan_cached_blocks, BlockSource, ChainState,
        CommitmentTreeRoot,
    },
    scanning::{ScanPriority, ScanRange},
    WalletCommitmentTrees, WalletRead, WalletWrite,
};
use zcash_client_backend::proto::service::{
    self, compact_tx_streamer_client::CompactTxStreamerClient, BlockId,
};
use zcash_client_sqlite::{chain::BlockMeta, FsBlockDb, FsBlockDbError};
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::BlockHeight;

use crate::network::ZNetwork;
use crate::wallet::open::{block_path, WriteDb};

const BATCH_SIZE: u32 = 10_000;

/// Download Sapling + Orchard note-commitment subtree roots and hand them to the wallet.
/// Run once at startup (and cheaply repeatable).
pub async fn update_subtree_roots(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WriteDb,
) -> anyhow::Result<()> {
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Sapling);
    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = sapling::Node::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;
    db_data.put_sapling_subtree_roots(0, &sapling_roots)?;

    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Orchard);
    let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = MerkleHashOrchard::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;
    db_data.put_orchard_subtree_roots(0, &orchard_roots)?;

    Ok(())
}

async fn download_blocks(
    client: &mut CompactTxStreamerClient<Channel>,
    wallet_dir: &Path,
    // Held across `.await`; must be `&mut` (not `&`) so the future stays `Send`, since
    // `FsBlockDb` is `Send` but not `Sync`.
    db_cache: &mut FsBlockDb,
    scan_range: &ScanRange,
) -> anyhow::Result<Vec<BlockMeta>> {
    info!("Fetching {}", scan_range);
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
        pool_types: Default::default(),
    };
    let block_meta_stream = client
        .get_block_range(range)
        .await
        .map_err(anyhow::Error::from)?
        .into_inner()
        .and_then(|block| {
            let wallet_dir = wallet_dir.to_owned();
            async move {
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

                let encoded = block.encode_to_vec();
                let mut block_file = File::create(block_path(&wallet_dir, &meta)).await?;
                block_file.write_all(&encoded).await?;
                Ok(meta)
            }
        });
    tokio::pin!(block_meta_stream);

    let mut block_meta = vec![];
    while let Some(block) = block_meta_stream.try_next().await? {
        block_meta.push(block);
    }

    db_cache
        .write_block_metadata(&block_meta)
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok(block_meta)
}

async fn download_chain_state(
    client: &mut CompactTxStreamerClient<Channel>,
    block_height: BlockHeight,
) -> anyhow::Result<ChainState> {
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;
    Ok(tree_state.into_inner().to_chain_state()?)
}

fn delete_cached_blocks(wallet_dir: &Path, block_meta: Vec<BlockMeta>) {
    for meta in block_meta {
        if let Err(e) = std::fs::remove_file(block_path(wallet_dir, &meta)) {
            warn!("Failed to remove cached block {:?}: {}", meta, e);
        }
    }
}

/// Scan a downloaded range; handle continuity (reorg) errors by rewinding. Returns whether
/// the suggested scan ranges changed materially.
fn scan_blocks(
    params: &ZNetwork,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
) -> anyhow::Result<bool> {
    info!("Scanning {}", scan_range);
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
            let rewind_height = err.at_height().saturating_sub(10);
            info!(
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                rewind_height
            );
            db_data.truncate_to_height(rewind_height)?;
            db_cache
                .with_blocks(Some(rewind_height + 1), None, |block| {
                    let meta = BlockMeta {
                        height: block.height(),
                        block_hash: block.hash(),
                        block_time: block.time,
                        sapling_outputs_count: 0,
                        orchard_actions_count: 0,
                    };
                    std::fs::remove_file(block_path(wallet_dir, &meta))
                        .map_err(|e| ChainError::<(), _>::BlockSource(FsBlockDbError::Fs(e)))
                })
                .map_err(|e| anyhow!("{:?}", e))?;
            db_cache
                .truncate_to_height(rewind_height)
                .map_err(|e| anyhow!("{:?}", e))?;
            Ok(true)
        }
        Ok(_) => {
            let latest_ranges = db_data.suggest_scan_ranges()?;
            Ok(latest_ranges
                .first()
                .map(|range| range.priority() > scan_range.priority())
                .unwrap_or(false))
        }
        Err(e) => Err(anyhow!("{:?}", e)),
    }
}

/// Process at most one batch of work. Returns `true` if a batch was scanned (caller should
/// call again), `false` if there are no pending scan ranges (wallet is caught up).
pub async fn sync_one_batch(
    client: &mut CompactTxStreamerClient<Channel>,
    params: &ZNetwork,
    wallet_dir: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WriteDb,
) -> anyhow::Result<bool> {
    let scan_ranges = db_data.suggest_scan_ranges()?;
    let Some(first) = scan_ranges.first() else {
        return Ok(false);
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

    let block_meta = download_blocks(client, wallet_dir, db_cache, &scan_range).await?;

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
        tokio::task::block_in_place(|| {
            scan_blocks(params, wallet_dir, db_cache, db_data, &chain_state, &scan_range)
        })?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Remove the downloaded compact blocks whether the scan succeeded or failed, so a transient
    // error (or a reorg-shifted range) can't strand cache files on disk.
    delete_cached_blocks(wallet_dir, block_meta);
    result?;
    Ok(true)
}
