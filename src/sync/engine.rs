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
            // NB: truncation requires a note-commitment-tree checkpoint at or below the
            // target, and per-block checkpoints exist only for scanned blocks that carried
            // shielded outputs (virtually all real blocks). On a fully-empty stretch this
            // errors (RequestedRewindInvalid) and the range is retried; rewinding through
            // such a stretch would need an upstream librustzcash API.
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
            scan_blocks(&net, wd, &mut db_cache, &mut db_data, &from, &range(h, h + 1))
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
        let worked = scan_blocks(
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
        assert!(worked, "a rewind reports that the scan ranges changed");

        // The rewind: continuity broke at 11, so the wallet rewound to 11 - 10 = 1...
        assert_eq!(max_scanned(&db_data), Some(1), "wallet truncated to the rewind height");
        // ...the block cache is truncated to match...
        assert_eq!(
            db_cache.get_max_cached_height().expect("max cached height"),
            Some(BlockHeight::from_u32(1)),
            "cache truncated to the rewind height"
        );
        // ...and the now-stale cached block files above it are deleted from disk.
        assert!(block_path(wd, &metas_a[0]).exists(), "block 1\'s file survives");
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
            &net,
            wd,
            &mut db_cache,
            &mut db_data,
            &chain_state(1, fake_hash(0xA1, 1), &frontier_at_1),
            &range(2, 13),
        )
        .expect("scan the replacement chain");
        assert_eq!(max_scanned(&db_data), Some(12), "recovered past the old tip");
    }
}
