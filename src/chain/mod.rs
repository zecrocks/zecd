//! The chain-data abstraction: everything the wallet needs from "upstream" (chain tip,
//! compact blocks, tree state, subtree roots, tx broadcast/fetch, mempool visibility),
//! expressed as the [`ChainSource`] trait. The one backend is [`zebra::ZebraSource`] - a
//! native zebrad JSON-RPC client that derives the data directly from a local full node
//! (`getblock`, `z_gettreestate`, `z_getsubtreesbyindex`, `sendrawtransaction`,
//! `getrawmempool`, …).
//!
//! Everything above this trait - the sync engine, reorg recovery, the rebroadcast loop, the
//! mempool-driven 0-conf flow - is backend-agnostic. [`AnySource`] is the enum the actor
//! stores; a future backend (e.g. an embedded Zaino service) is one more variant + impl.

pub mod zebra;

use std::future::Future;

use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{ShieldedProtocol, TxId};

/// The chain tip as reported by the upstream. `hash` is in internal byte order (reverse of
/// the familiar display hex); it may be empty if the upstream didn't report one.
#[derive(Clone, Debug)]
pub struct ChainTip {
    pub height: u64,
    pub hash: Vec<u8>,
}

/// Upstream identity, used by the wrong-chain guard. `chain_name` follows zcashd's
/// `getblockchaininfo.chain` / lightwalletd's `chain_name`: `"main"`, `"test"`, `"regtest"`.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub chain_name: String,
}

/// The upstream's verdict on a broadcast transaction. `error_code == 0` means accepted;
/// anything else is an explicit rejection (the node examined the tx and refused it), which
/// callers surface as `-26` - as distinct from a transport failure, which is the method's
/// `Err` and means "unknown whether anyone saw it".
#[derive(Clone, Debug)]
pub struct BroadcastOutcome {
    pub error_code: i32,
    pub error_message: String,
}

impl BroadcastOutcome {
    pub fn accepted() -> Self {
        BroadcastOutcome {
            error_code: 0,
            error_message: String::new(),
        }
    }
    pub fn is_accepted(&self) -> bool {
        self.error_code == 0
    }
}

/// A transaction fetched from the upstream: raw bytes plus the mined height when the
/// upstream knows it (`None` for mempool transactions).
#[derive(Clone, Debug)]
pub struct FetchedTx {
    pub data: Vec<u8>,
    pub mined_height: Option<u32>,
}

/// One note-commitment-subtree root: the raw node hash (protocol byte order, NOT reversed)
/// and the height of the block that completed the subtree.
#[derive(Clone, Debug)]
pub struct SubtreeRootInfo {
    pub root_hash: Vec<u8>,
    pub completing_height: u32,
}

/// A connected chain-data backend. All methods take `&mut self` (the lightwalletd client
/// requires it) and return `Send` futures so the wallet actor task stays spawnable.
///
/// Error contract: an `Err` from any method is a transport-class failure - the caller should
/// drop the connection and reconnect/fail over. Application-level outcomes that must not
/// kill the connection are encoded in the `Ok` value instead: an upstream tx rejection is
/// `Ok(BroadcastOutcome { error_code != 0, .. })`, an unknown txid is `Ok(None)`.
pub trait ChainSource: Send {
    /// The current chain tip (lightwalletd `GetLatestBlock`; zebra `getblockchaininfo`).
    fn latest_block(&mut self) -> impl Future<Output = anyhow::Result<ChainTip>> + Send;

    /// The commitment-tree state at `height` (lightwalletd `GetTreeState`; zebra
    /// `z_gettreestate`), in lightwalletd's protobuf form so both
    /// `TreeState::to_chain_state` and `AccountBirthday::from_treestate` work unchanged.
    fn tree_state(
        &mut self,
        height: BlockHeight,
    ) -> impl Future<Output = anyhow::Result<service::TreeState>> + Send;

    /// Stream the compact blocks for `start..=end` in order (lightwalletd `GetBlockRange`;
    /// zebra `getblock` + local full-block→CompactBlock conversion).
    fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> impl Future<Output = anyhow::Result<CompactBlockStream>> + Send;

    /// All note-commitment-subtree roots for `protocol`, from index 0 (lightwalletd
    /// `GetSubtreeRoots`; zebra `z_getsubtreesbyindex`).
    fn subtree_roots(
        &mut self,
        protocol: ShieldedProtocol,
    ) -> impl Future<Output = anyhow::Result<Vec<SubtreeRootInfo>>> + Send;

    /// Upstream identity/liveness (lightwalletd `GetLightdInfo`; zebra `getblockchaininfo`).
    fn server_info(&mut self) -> impl Future<Output = anyhow::Result<ServerInfo>> + Send;

    /// Broadcast raw transaction bytes (lightwalletd `SendTransaction`; zebra
    /// `sendrawtransaction`). See the trait-level error contract.
    fn broadcast_tx(
        &mut self,
        data: Vec<u8>,
    ) -> impl Future<Output = anyhow::Result<BroadcastOutcome>> + Send;

    /// Fetch a transaction by txid (lightwalletd `GetTransaction`; zebra
    /// `getrawtransaction`). `Ok(None)` when the upstream does not know the txid.
    fn fetch_tx(
        &mut self,
        txid: TxId,
    ) -> impl Future<Output = anyhow::Result<Option<FetchedTx>>> + Send;

    /// Subscribe to the mempool (lightwalletd `GetMempoolStream`; zebra a `getrawmempool`
    /// poller). The stream yields the current mempool and newly-arriving transactions, and
    /// **closes (yields `None`) when a new block arrives** - the actor relies on that as its
    /// sync-now signal, so both backends must preserve it.
    fn subscribe_mempool(&mut self) -> impl Future<Output = anyhow::Result<MempoolStream>> + Send;
}

/// The connected backend the actor and `init` hold. Delegates every [`ChainSource`] method to
/// the inner backend. (A single-variant enum today; a future backend is one more variant.)
pub enum AnySource {
    Zebra(zebra::ZebraSource),
}

impl ChainSource for AnySource {
    async fn latest_block(&mut self) -> anyhow::Result<ChainTip> {
        match self {
            AnySource::Zebra(s) => s.latest_block().await,
        }
    }

    async fn tree_state(&mut self, height: BlockHeight) -> anyhow::Result<service::TreeState> {
        match self {
            AnySource::Zebra(s) => s.tree_state(height).await,
        }
    }

    async fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> anyhow::Result<CompactBlockStream> {
        match self {
            AnySource::Zebra(s) => s.compact_block_range(start, end).await,
        }
    }

    async fn subtree_roots(
        &mut self,
        protocol: ShieldedProtocol,
    ) -> anyhow::Result<Vec<SubtreeRootInfo>> {
        match self {
            AnySource::Zebra(s) => s.subtree_roots(protocol).await,
        }
    }

    async fn server_info(&mut self) -> anyhow::Result<ServerInfo> {
        match self {
            AnySource::Zebra(s) => s.server_info().await,
        }
    }

    async fn broadcast_tx(&mut self, data: Vec<u8>) -> anyhow::Result<BroadcastOutcome> {
        match self {
            AnySource::Zebra(s) => s.broadcast_tx(data).await,
        }
    }

    async fn fetch_tx(&mut self, txid: TxId) -> anyhow::Result<Option<FetchedTx>> {
        match self {
            AnySource::Zebra(s) => s.fetch_tx(txid).await,
        }
    }

    async fn subscribe_mempool(&mut self) -> anyhow::Result<MempoolStream> {
        match self {
            AnySource::Zebra(s) => s.subscribe_mempool().await,
        }
    }
}

/// An in-order stream of compact blocks for one requested range.
pub enum CompactBlockStream {
    Zebra(zebra::ZebraBlockStream),
}

impl CompactBlockStream {
    /// The next block, `Ok(None)` at end of range, or a transport-class error.
    pub async fn next(&mut self) -> anyhow::Result<Option<CompactBlock>> {
        match self {
            CompactBlockStream::Zebra(s) => s.next().await,
        }
    }
}

/// A live mempool subscription. Yields raw transactions; `Ok(None)` means the upstream
/// closed the stream because a new block arrived (the actor's sync-now signal); `Err` is a
/// transport-class failure (the actor just drops the subscription).
pub enum MempoolStream {
    Zebra(zebra::ZebraMempoolStream),
}

impl MempoolStream {
    pub async fn message(&mut self) -> anyhow::Result<Option<service::RawTransaction>> {
        match self {
            MempoolStream::Zebra(s) => s.message().await,
        }
    }
}
