//! Typed blockchain RPCs: chain/sync overview, block lookups, and the blocking `waitfor*`
//! family. Response shapes follow `rpc/blockchain.rs`; heights are the wallet's
//! fully-scanned view (`blocks` = accurate-balances height, `headers` = known tip).

use serde_json::json;

use super::{Client, ClientError};

/// `getblockchaininfo` (`rpc/blockchain.rs::getblockchaininfo`).
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BlockchainInfo {
    /// Network name (`main`/`test`/`regtest`).
    pub chain: String,
    /// The fully-scanned height - the height at which balances/history are accurate.
    pub blocks: u32,
    /// The known chain tip; `blocks < headers` while syncing, as bitcoind reports IBD.
    pub headers: u32,
    /// Empty in the brief window before anything is scanned.
    pub bestblockhash: String,
    pub time: i64,
    pub mediantime: i64,
    /// Height-based scan progress in [0, 1] (fully-scanned vs tip).
    pub verificationprogress: f64,
    /// True until the wallet is ready to serve full history (block scan caught up AND the
    /// transaction-enhancement backlog drained).
    pub initialblockdownload: bool,
    pub pruned: bool,
    pub warnings: String,
}

/// The `{hash, height}` result of the `waitfor*` family - the wallet's best (fully-scanned)
/// block, returned both when the wait was satisfied and when it timed out. A timeout is NOT
/// an error (Bitcoin Core's convention): compare `height`/`hash` against what you waited for.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BlockRef {
    /// Empty in the brief window before anything is scanned.
    pub hash: String,
    pub height: u32,
}

/// The `waitforsync` result (`rpc/blockchain.rs::waitforsync`): the wallet's best scanned block
/// plus the two enhancement fields. Returned both when the wait was satisfied and when it timed
/// out, so `synced` is the field to branch on - a timeout is not an error.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SyncState {
    /// Empty in the brief window before anything is scanned.
    pub hash: String,
    pub height: u32,
    /// The upstream's chain tip, against which `height` is the scanned progress - so
    /// "scanned 3,366,176 of 3,366,250" needs no second connection. `None` until the node has
    /// learned a tip (before its first successful connect).
    #[serde(default)]
    pub chain_tip: Option<u32>,
    /// True only when the block scan has reached the tip *and* the enhancement backlog is
    /// empty - i.e. history and memos are complete as of `height`.
    pub synced: bool,
    /// Outstanding transaction-enhancement requests; `0` when fully synced.
    pub pending_enhancements: u64,
    /// The height through which memos are known to be present (see
    /// `wallet::SyncStatus::enhanced_through`). `None` means "not currently known", never
    /// "everything is enhanced" - a consumer advancing a memo cursor must hold it still.
    pub enhanced_through: Option<u32>,
}

/// `getblockheader` verbose result (`rpc/blockchain.rs::getblockheader`). Served from the
/// wallet's scanned-blocks table, so only the fields a compact block carries are present -
/// no version/merkleroot/nonce/bits/difficulty.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BlockHeader {
    pub hash: String,
    pub confirmations: i64,
    pub height: u32,
    pub time: i64,
    pub mediantime: i64,
    /// Omitted when the previous block is outside the wallet's scan range.
    pub previousblockhash: Option<String>,
    /// Omitted on the tip (as Bitcoin Core does).
    pub nextblockhash: Option<String>,
}

impl Client<'_> {
    /// `getblockchaininfo`: chain/sync overview.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo, ClientError> {
        self.call_typed("getblockchaininfo", vec![]).await
    }

    /// `getblockcount`: the fully-scanned height (where balances are accurate).
    pub async fn get_block_count(&self) -> Result<u32, ClientError> {
        self.call_typed("getblockcount", vec![]).await
    }

    /// `getbestblockhash`: the hash of the [`Client::get_block_count`] block.
    pub async fn get_best_block_hash(&self) -> Result<String, ClientError> {
        self.call_typed("getbestblockhash", vec![]).await
    }

    /// `getblockhash <height>`: answered from the wallet's scanned range (out of range: -8).
    pub async fn get_block_hash(&self, height: u32) -> Result<String, ClientError> {
        self.call_typed("getblockhash", vec![json!(height)]).await
    }

    /// `getblockheader <blockhash>`: the verbose header (the only form a compact-block
    /// wallet can serve; `verbose=false` is rejected on the wire).
    pub async fn get_block_header(&self, blockhash: &str) -> Result<BlockHeader, ClientError> {
        self.call_typed("getblockheader", vec![json!(blockhash)])
            .await
    }

    /// `waitfornewblock ( timeout_ms )`: block until the best *scanned* block changes.
    /// `timeout_ms` in milliseconds, `None`/0 = wait indefinitely; a timeout returns the
    /// current block rather than erroring (see [`BlockRef`]).
    pub async fn wait_for_new_block(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<BlockRef, ClientError> {
        let params = Self::positional(vec![timeout_ms.map(|t| json!(t))]);
        self.call_typed("waitfornewblock", params).await
    }

    /// `waitforblock <blockhash> ( timeout_ms )`: block until `blockhash` is the best scanned
    /// block (tip-only match, like Bitcoin Core). Timeout semantics as [`BlockRef`].
    pub async fn wait_for_block(
        &self,
        blockhash: &str,
        timeout_ms: Option<u64>,
    ) -> Result<BlockRef, ClientError> {
        let params = Self::positional(vec![Some(json!(blockhash)), timeout_ms.map(|t| json!(t))]);
        self.call_typed("waitforblock", params).await
    }

    /// `waitforblockheight <height> ( timeout_ms )`: block until the wallet has scanned to at
    /// least `height` - the correct "has the wallet caught up?" primitive (a balance is not:
    /// mempool receives credit at 0 conf). Timeout semantics as [`BlockRef`].
    pub async fn wait_for_block_height(
        &self,
        height: u32,
        timeout_ms: Option<u64>,
    ) -> Result<BlockRef, ClientError> {
        let params = Self::positional(vec![Some(json!(height)), timeout_ms.map(|t| json!(t))]);
        self.call_typed("waitforblockheight", params).await
    }

    /// `waitforsync ( timeout_ms )`: start a sync pass now, then block until the wallet is fully
    /// caught up - block scan at the tip *and* the enhancement backlog drained, which is what
    /// makes memos readable. `timeout_ms` of `None`/`0` waits indefinitely; a timeout is not an
    /// error, so branch on [`SyncState::synced`].
    pub async fn wait_for_sync(&self, timeout_ms: Option<u64>) -> Result<SyncState, ClientError> {
        let params = Self::positional(vec![timeout_ms.map(|t| json!(t))]);
        self.call_typed("waitforsync", params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixtures for `waitforsync`: the satisfied case (drained backlog, a known watermark) and
    /// the timed-out case, where `synced` is false and the watermark can be absent - the shape a
    /// caller must not read as "everything is enhanced".
    #[test]
    fn sync_state_decodes_both_outcomes() {
        let synced: SyncState = serde_json::from_value(serde_json::json!({
            "hash": "0000000000000000000000000000000000000000000000000000000000abc123",
            "height": 240,
            "chain_tip": 240,
            "synced": true,
            "pending_enhancements": 0,
            "enhanced_through": 240,
        }))
        .unwrap();
        assert!(synced.synced);
        assert_eq!(synced.pending_enhancements, 0);
        assert_eq!(synced.enhanced_through, Some(240));
        assert_eq!(synced.chain_tip, Some(240));

        // Mid-sync is the case `chain_tip` exists for: `height` alone cannot express progress,
        // since what it is measured against is the tip.
        let timed_out: SyncState = serde_json::from_value(serde_json::json!({
            "hash": "",
            "height": 100,
            "chain_tip": 400,
            "synced": false,
            "pending_enhancements": 4096,
            "enhanced_through": serde_json::Value::Null,
        }))
        .unwrap();
        assert!(!timed_out.synced);
        assert_eq!(timed_out.pending_enhancements, 4096);
        assert_eq!(timed_out.enhanced_through, None);
        assert_eq!(timed_out.chain_tip, Some(400));

        // A tip is not known until the first successful connect, and a node that predates the
        // field omits it entirely; both decode as "unknown" rather than failing.
        let no_tip: SyncState = serde_json::from_value(serde_json::json!({
            "hash": "",
            "height": 0,
            "synced": false,
            "pending_enhancements": 0,
            "enhanced_through": serde_json::Value::Null,
        }))
        .unwrap();
        assert_eq!(no_tip.chain_tip, None);
    }

    /// Fixture captured from a synced regtest wallet's `getblockchaininfo`.
    #[test]
    fn blockchain_info_decodes() {
        let v = serde_json::json!({
            "chain": "regtest",
            "blocks": 120,
            "headers": 120,
            "bestblockhash": "0a".repeat(32),
            "difficulty": 1.0,
            "time": 1_723_000_000i64,
            "mediantime": 1_722_999_000i64,
            "verificationprogress": 1.0,
            "initialblockdownload": false,
            "size_on_disk": 0,
            "pruned": false,
            "warnings": "",
        });
        let info: BlockchainInfo = serde_json::from_value(v).unwrap();
        assert_eq!(info.blocks, 120);
        assert_eq!(info.chain, "regtest");
        assert!(!info.initialblockdownload);
    }

    /// Fixture: a header mid-chain carries both links; the tip omits `nextblockhash`.
    #[test]
    fn block_header_decodes_with_optional_links() {
        let mid = serde_json::json!({
            "hash": "ab".repeat(32),
            "confirmations": 3,
            "height": 10,
            "time": 1_723_000_000i64,
            "mediantime": 1_723_000_000i64,
            "previousblockhash": "cd".repeat(32),
            "nextblockhash": "ef".repeat(32),
        });
        let h: BlockHeader = serde_json::from_value(mid).unwrap();
        assert!(h.previousblockhash.is_some() && h.nextblockhash.is_some());

        let tip = serde_json::json!({
            "hash": "ab".repeat(32),
            "confirmations": 1,
            "height": 12,
            "time": 1_723_000_100i64,
            "mediantime": 1_723_000_050i64,
            "previousblockhash": "cd".repeat(32),
        });
        let h: BlockHeader = serde_json::from_value(tip).unwrap();
        assert!(h.nextblockhash.is_none());
    }

    /// The waitfor* result decodes with the empty-hash pre-scan form too.
    #[test]
    fn block_ref_decodes() {
        let v = serde_json::json!({ "hash": "", "height": 0 });
        let r: BlockRef = serde_json::from_value(v).unwrap();
        assert_eq!(r.height, 0);
        assert!(r.hash.is_empty());
    }
}
