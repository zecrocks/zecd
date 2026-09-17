//! The in-memory [`BlockSource`] holding the batch currently being scanned.
//!
//! zecd's block cache used to be `FsBlockDb`: one file per compact block under `blocks/`,
//! indexed by a `blockmeta.sqlite` metadata table. That layout is built for a cache that
//! *outlives* a scan - a wallet keeping blocks around so a later rescan need not re-download
//! them - and zecd never used it that way. `sync_one_batch` downloads a range, scans it, and
//! deletes it before the next range starts, so nothing survived one batch. The files bought
//! nothing and cost, per 10,000-block batch: 10,000 `create` + `write` syscalls during the
//! download, 20,000 `open` + `read` during the scan (`scan_cached_blocks` walks the range
//! twice, once to fill its trial-decryption batch runners and once to scan), 10,000 `unlink`
//! afterwards, and a whole class of consistency work keeping the files and the metadata rows
//! in step across reorgs and upgrades. Measured on a busy testnet restore the cleanup alone
//! was 10 s of a 220 s scan, and every one of those syscalls is a place a slow disk or a virus
//! scanner opening each new file could stall the scan.
//!
//! A batch is small. The whole birthday-to-tip range for that wallet was 82 MB of compact
//! blocks across 24 batches, the largest single batch about 29 MB (a transaction burst). So the
//! in-flight batch lives here instead, and there is no on-disk block cache at all: a reorg
//! discards the batch along with the range it belonged to, which is what deleting the files
//! did, and there are no metadata rows to truncate.
//!
//! Blocks are kept in their wire encoding. `BlockSource::with_blocks` hands each block to the
//! scanner *by value*, so a decoded cache would have to clone on every pass, and a clone of a
//! `CompactBlock` allocates the same vectors a decode does - measured level with decoding.
//! The encoded form is then the better choice on the tie-break: one batch of testnet blocks is
//! a few megabytes encoded against tens decoded, and the dense ranges are exactly where the
//! difference matters.

use std::convert::Infallible;

use prost::Message as _;
use zcash_client_backend::data_api::chain::{error::Error as ChainError, BlockSource};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_protocol::consensus::BlockHeight;

/// One batch of compact blocks, held in memory for the scan that follows the download that
/// produced them.
///
/// Blocks are pushed in ascending height order as they stream in, which is the order
/// [`BlockSource::with_blocks`] must yield them in, so serving a scan is a slice walk.
#[derive(Debug, Default)]
pub struct MemBlockCache {
    /// The batch, in its wire encoding, parallel to `heights`.
    blocks: Vec<Vec<u8>>,
    /// Each block's height, so a pass can skip below its `from_height` without decoding.
    heights: Vec<u32>,
}

impl MemBlockCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a downloaded block. Callers push in ascending height order; a block below the
    /// last one pushed is a caller bug, and is refused rather than served out of order.
    pub fn push(&mut self, height: BlockHeight, encoded: Vec<u8>) {
        let height = u32::from(height);
        if let Some(last) = self.heights.last() {
            assert!(
                height > *last,
                "blocks must be pushed in ascending height order ({height} after {last})"
            );
        }
        self.heights.push(height);
        self.blocks.push(encoded);
    }

    /// Blocks held.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// The highest height held, if any.
    pub fn last_height(&self) -> Option<BlockHeight> {
        self.heights.last().map(|h| BlockHeight::from_u32(*h))
    }

    /// Encoded bytes held.
    pub fn byte_len(&self) -> u64 {
        self.blocks.iter().map(|b| b.len() as u64).sum()
    }
}

/// `Infallible`: the bytes served were encoded by this process, so nothing here can fail. A
/// decode failure would mean memory corruption, which is not an error to report to the scan
/// loop and retry.
impl BlockSource for MemBlockCache {
    type Error = Infallible;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), ChainError<DbErrT, Self::Error>>
    where
        F: FnMut(CompactBlock) -> Result<(), ChainError<DbErrT, Self::Error>>,
    {
        let from = from_height.map_or(0, u32::from);
        let start = self.heights.partition_point(|h| *h < from);
        let served = self.blocks.iter().skip(start);
        let served: Box<dyn Iterator<Item = &Vec<u8>>> = match limit {
            Some(limit) => Box::new(served.take(limit)),
            None => Box::new(served),
        };
        for encoded in served {
            let block = CompactBlock::decode(&encoded[..])
                .expect("a block this process encoded decodes again");
            with_block(block)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::proto::compact_formats as pb;

    fn encoded(height: u32) -> Vec<u8> {
        pb::CompactBlock {
            height: u64::from(height),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn cache(heights: impl IntoIterator<Item = u32>) -> MemBlockCache {
        let mut cache = MemBlockCache::new();
        for h in heights {
            cache.push(BlockHeight::from_u32(h), encoded(h));
        }
        cache
    }

    fn heights_served(cache: &MemBlockCache, from: Option<u32>, limit: Option<usize>) -> Vec<u64> {
        let mut seen = vec![];
        cache
            .with_blocks::<_, Infallible>(from.map(BlockHeight::from_u32), limit, |b| {
                seen.push(b.height);
                Ok(())
            })
            .unwrap();
        seen
    }

    /// The contract `scan_cached_blocks` relies on: the batch in height order, from the
    /// requested height, capped by the limit.
    #[test]
    fn serves_from_height_in_order_under_the_limit() {
        let cache = cache(100..110);
        assert_eq!(
            heights_served(&cache, Some(103), Some(4)),
            [103, 104, 105, 106]
        );
        assert_eq!(heights_served(&cache, None, None).len(), 10);
        assert_eq!(heights_served(&cache, Some(109), None), [109]);
        assert!(heights_served(&cache, Some(110), None).is_empty());
        assert_eq!(cache.last_height(), Some(BlockHeight::from_u32(109)));
    }

    /// `scan_cached_blocks` walks the range twice; the second pass must not come up short.
    #[test]
    fn a_second_pass_yields_the_same_blocks() {
        let cache = cache(1..5);
        assert_eq!(heights_served(&cache, None, None), [1, 2, 3, 4]);
        assert_eq!(heights_served(&cache, None, None), [1, 2, 3, 4]);
    }

    #[test]
    fn an_empty_cache_serves_nothing() {
        let cache = MemBlockCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.byte_len(), 0);
        assert_eq!(cache.last_height(), None);
        assert!(heights_served(&cache, None, None).is_empty());
    }

    #[test]
    #[should_panic(expected = "ascending height order")]
    fn pushing_out_of_order_is_a_caller_bug() {
        let mut cache = cache([5]);
        cache.push(BlockHeight::from_u32(4), encoded(4));
    }
}
