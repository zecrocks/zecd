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
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::{ShieldedPool, TxId};

/// The chain tip as reported by the upstream. `hash` is in internal byte order (reverse of
/// the familiar display hex); it may be empty if the upstream didn't report one.
#[derive(Clone, Debug)]
pub struct ChainTip {
    pub height: u64,
    pub hash: Vec<u8>,
}

/// A transparent output observed upstream, carrying exactly what
/// `WalletTransparentOutput::from_parts` needs so the actor can feed it to
/// `WalletWrite::put_received_transparent_utxo` - the path by which a wallet learns of transparent
/// *receives* (`decrypt_and_store` only handles shielded outputs).
///
/// Two sources produce these, with slightly different semantics:
///  * the address index (`getaddressutxos`) returns only **currently-unspent** outputs, mined,
///    for a given set of addresses; and
///  * the block scan ([`CompactBlockStream::next`] with `include_transparent`) yields **every**
///    transparent output in each scanned block (the matcher filters to the wallet's addresses).
///    Such an output may already have been spent in a later block; the spend is discovered
///    separately by the enhancement path (librustzcash's `TransactionsInvolvingAddress` request,
///    serviced via `getaddresstxids`), so recording it as a receive is correct.
///
/// `height` is the block height the output was mined at; for a mempool (0-conf) output it is
/// `None` (the matcher feeds that straight to `from_parts` as an unmined output).
#[derive(Clone, Debug)]
pub struct TransparentUtxo {
    /// Internal-byte-order txid of the funding transaction.
    pub txid: TxId,
    /// Output index within that transaction's `vout`.
    pub index: u32,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// The output's `script_pubkey` bytes.
    pub script: Vec<u8>,
    /// The height at which the output was mined, or `None` for a mempool (0-conf) output.
    pub height: Option<u32>,
    /// The full coinbase transaction this output belongs to, when it is a coinbase output
    /// (`None` for all non-coinbase outputs). The block scan already holds the parsed block, so
    /// this costs nothing extra; the sync engine stores it via `decrypt_and_store_transaction`
    /// when the output pays the wallet, which is what records `transactions.tx_index = 0` - the
    /// datum `zcash_client_sqlite` keys **every** coinbase rule on (the 100-block maturity clause
    /// and the `CoinbaseFilter` partition in `get_spendable_transparent_outputs`). Recorded via
    /// `put_received_transparent_utxo` alone, a coinbase UTXO would be silently misclassified as
    /// non-coinbase (spendable while immature, invisible to `z_shieldcoinbase`).
    pub coinbase_tx: Option<std::sync::Arc<zcash_primitives::transaction::Transaction>>,
}

/// Upstream identity, used by the wrong-chain guard. `chain_name` follows zcashd's
/// `getblockchaininfo.chain` / lightwalletd's `chain_name`: `"main"`, `"test"`, `"regtest"`.
///
/// The upgrade fields feed the outdated-build detector ([`unsupported_upgrades`]): the node
/// reached its chain tip by validating every activated upgrade, so what *it* reports is the
/// authoritative list of consensus rules this wallet must understand to scan that chain. All
/// three are best-effort - an upstream that doesn't report them yields an empty list / `None`,
/// which simply disables the detection (never an error).
#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub chain_name: String,
    /// The network upgrades the upstream node knows of (`getblockchaininfo.upgrades`), sorted
    /// by activation height. Empty when the upstream doesn't report them.
    pub upgrades: Vec<UpgradeInfo>,
    /// Consensus branch ID in force at the upstream's chain tip
    /// (`getblockchaininfo.consensus.chaintip`).
    pub tip_branch_id: Option<u32>,
    /// Consensus branch ID the next mined block will follow
    /// (`getblockchaininfo.consensus.nextblock`). Differs from the tip's only on the last
    /// pre-activation block.
    pub next_block_branch_id: Option<u32>,
}

/// One `getblockchaininfo.upgrades` entry, as the upstream reports it.
#[derive(Clone, Debug)]
pub struct UpgradeInfo {
    /// The upgrade's consensus branch ID (the map key, parsed from hex).
    pub branch_id: u32,
    /// The upstream's display name for the upgrade (e.g. `"NU6.3"`). Operator-trusted text -
    /// sanitize before echoing it into logs or errors.
    pub name: String,
    /// The height the upgrade activates (or activated) at, when reported.
    pub activation_height: Option<u32>,
    pub status: UpgradeStatus,
}

/// A `getblockchaininfo.upgrades` entry's `status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpgradeStatus {
    /// Announced with a future activation height.
    Pending,
    /// In force at the upstream's chain tip.
    Active,
    /// Anything else the upstream reports (zcashd's `"disabled"`, unrecognized strings).
    Other,
}

/// A network upgrade the upstream chain follows (or is about to follow) whose consensus branch
/// ID this zecd build does not recognize - the "this zecd is outdated" signal. When the NU6.3
/// (ironwood) upgrade activated, builds that predated it kept fetching post-activation blocks
/// they could not apply and looped on the same sync error forever with no explanation; this is
/// the datum that lets the actor say *why* instead.
#[derive(Clone, Debug)]
pub struct UnsupportedUpgrade {
    pub branch_id: u32,
    /// Upstream-reported name, or `"unknown upgrade"` when only a bare branch ID was seen.
    pub name: String,
    pub activation_height: Option<u32>,
    /// Whether the upgrade is already in force at the upstream tip (as opposed to pending at a
    /// future height).
    pub active: bool,
}

/// The network upgrades the upstream reports that this build's librustzcash does not recognize
/// (its [`BranchId`] enumeration is the complete set of consensus rules this build can scan
/// under). Only `active`/`pending` entries count - a disabled upgrade will never rule the
/// chain. The `consensus` branch IDs are a belt over the upgrades map: an unrecognized branch
/// ruling the tip (or the very next block) is reported as an active unsupported upgrade even
/// if the upgrades map omitted it.
pub fn unsupported_upgrades(info: &ServerInfo) -> Vec<UnsupportedUpgrade> {
    let known = |id: u32| BranchId::try_from(id).is_ok();
    let mut out: Vec<UnsupportedUpgrade> = info
        .upgrades
        .iter()
        .filter(|u| matches!(u.status, UpgradeStatus::Active | UpgradeStatus::Pending))
        .filter(|u| !known(u.branch_id))
        .map(|u| UnsupportedUpgrade {
            branch_id: u.branch_id,
            name: u.name.clone(),
            activation_height: u.activation_height,
            active: u.status == UpgradeStatus::Active,
        })
        .collect();
    for id in [info.tip_branch_id, info.next_block_branch_id]
        .into_iter()
        .flatten()
    {
        if !known(id) {
            match out.iter_mut().find(|u| u.branch_id == id) {
                // The chain is already (or imminently) governed by these rules; a map entry
                // still marked pending is promoted so callers treat it with active severity.
                Some(u) => u.active = true,
                None => out.push(UnsupportedUpgrade {
                    branch_id: id,
                    name: "unknown upgrade".to_string(),
                    activation_height: None,
                    active: true,
                }),
            }
        }
    }
    out
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
    /// zebra `getblock` + local full-block->CompactBlock conversion).
    ///
    /// When `include_transparent` is set, each streamed item also carries the block's transparent
    /// outputs (see [`CompactBlockStream::next`]) so the caller can discover transparent receives
    /// from the *same* full block it already fetched - no extra per-block or per-address request.
    /// Shielded-only wallets pass `false` so the (non-trivial) per-block transparent extraction is
    /// skipped entirely.
    fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
        include_transparent: bool,
    ) -> impl Future<Output = anyhow::Result<CompactBlockStream>> + Send;

    /// All note-commitment-subtree roots for `protocol`, from index 0 (lightwalletd
    /// `GetSubtreeRoots`; zebra `z_getsubtreesbyindex`).
    fn subtree_roots(
        &mut self,
        protocol: ShieldedPool,
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

    /// All txids that touch any of the given **transparent** addresses within the inclusive height
    /// range `[start, end]` (lightwalletd `GetTaddressTxids`; zebra `getaddresstxids`, which accepts
    /// a batch of addresses in one call). Compact blocks omit transparent inputs/outputs, so this is
    /// how the wallet discovers *mined* transparent receives and spends in order to enhance
    /// (fetch+store) them. Each address is the bare encoding (`t1…`/`tm…`). Ordering is not
    /// guaranteed, and txids may repeat across addresses (callers de-dupe / store idempotently).
    fn transparent_txids(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> impl Future<Output = anyhow::Result<Vec<TxId>>> + Send;

    /// All currently-**unspent** transparent UTXOs paying any of the given addresses
    /// (zcashd/zebra `getaddresstxids`'s sibling `getaddressutxos`; lightwalletd `GetAddressUtxos`).
    /// This is how the wallet discovers transparent **receives**: librustzcash's
    /// `decrypt_and_store` only records shielded outputs, so received transparent UTXOs come from
    /// this query and are stored via `WalletWrite::put_received_transparent_utxo` (mirrors
    /// `zcash_client_backend::sync`). Returns the wallet-relevant fields per UTXO; ordering is not
    /// guaranteed.
    fn get_address_utxos(
        &mut self,
        addresses: Vec<String>,
    ) -> impl Future<Output = anyhow::Result<Vec<TransparentUtxo>>> + Send;

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
        include_transparent: bool,
    ) -> anyhow::Result<CompactBlockStream> {
        match self {
            AnySource::Zebra(s) => s.compact_block_range(start, end, include_transparent).await,
        }
    }

    async fn subtree_roots(
        &mut self,
        protocol: ShieldedPool,
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

    async fn transparent_txids(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> anyhow::Result<Vec<TxId>> {
        match self {
            AnySource::Zebra(s) => s.transparent_txids(addresses, start, end).await,
        }
    }

    async fn get_address_utxos(
        &mut self,
        addresses: Vec<String>,
    ) -> anyhow::Result<Vec<TransparentUtxo>> {
        match self {
            AnySource::Zebra(s) => s.get_address_utxos(addresses).await,
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
    /// The next block paired with its transparent outputs, `Ok(None)` at end of range, or a
    /// transport-class error.
    ///
    /// The transparent-output vector is the block's full set of transparent `vout`s (every
    /// output, not just the wallet's - the caller matches against its address set); it is always
    /// empty unless the stream was opened with `include_transparent`. Carrying it here lets the
    /// wallet discover transparent receives from the block it already downloaded for the shielded
    /// scan, at no extra fetch.
    pub async fn next(&mut self) -> anyhow::Result<Option<(CompactBlock, Vec<TransparentUtxo>)>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn info(upgrades: Vec<UpgradeInfo>, tip: Option<u32>, next: Option<u32>) -> ServerInfo {
        ServerInfo {
            chain_name: "main".to_string(),
            upgrades,
            tip_branch_id: tip,
            next_block_branch_id: next,
        }
    }

    fn upgrade(branch_id: u32, name: &str, height: u32, status: UpgradeStatus) -> UpgradeInfo {
        UpgradeInfo {
            branch_id,
            name: name.to_string(),
            activation_height: Some(height),
            status,
        }
    }

    /// NU6 (0xc8e71055) and NU5 (0xc2d6d0b4) are branch IDs every supported build knows;
    /// 0xdeadbeef stands in for a future upgrade this build predates.
    const KNOWN_NU5: u32 = 0xc2d6_d0b4;
    const KNOWN_NU6: u32 = 0xc8e7_1055;
    const FUTURE: u32 = 0xdead_beef;

    /// A fully-recognized upgrade list (the healthy steady state) reports nothing, whatever the
    /// statuses - the detector must never cry wolf on a chain this build fully understands.
    #[test]
    fn all_known_upgrades_are_supported() {
        let i = info(
            vec![
                upgrade(KNOWN_NU5, "NU5", 1_687_104, UpgradeStatus::Active),
                upgrade(KNOWN_NU6, "NU6", 2_726_400, UpgradeStatus::Active),
            ],
            Some(KNOWN_NU6),
            Some(KNOWN_NU6),
        );
        assert!(unsupported_upgrades(&i).is_empty());
    }

    /// An upstream that doesn't report upgrades at all (empty map, no consensus IDs) disables
    /// the detection rather than erroring or guessing.
    #[test]
    fn absent_upgrade_data_reports_nothing() {
        assert!(unsupported_upgrades(&info(vec![], None, None)).is_empty());
    }

    /// The core outdated-build case: the upstream lists an upgrade whose branch ID this build's
    /// `BranchId` cannot parse. Active and pending entries are both reported (pending is the
    /// advance warning that lets an operator update *before* the network switches); a
    /// disabled/other entry is not - it will never rule the chain.
    #[test]
    fn unknown_branch_ids_are_reported_with_their_status() {
        let i = info(
            vec![
                upgrade(KNOWN_NU6, "NU6", 2_726_400, UpgradeStatus::Active),
                upgrade(FUTURE, "NU-Future", 4_100_000, UpgradeStatus::Active),
                upgrade(0xfeed_f00d, "NU-Later", 5_000_000, UpgradeStatus::Pending),
                upgrade(0x0bad_cafe, "NU-Disabled", 0, UpgradeStatus::Other),
            ],
            None,
            None,
        );
        let got = unsupported_upgrades(&i);
        assert_eq!(got.len(), 2, "active + pending unknown, never disabled");
        assert!(got[0].active && got[0].branch_id == FUTURE);
        assert_eq!(got[0].name, "NU-Future");
        assert_eq!(got[0].activation_height, Some(4_100_000));
        assert!(!got[1].active && got[1].branch_id == 0xfeed_f00d);
    }

    /// The consensus branch IDs are the belt over the upgrades map: an unrecognized branch
    /// ruling the tip is reported as active-unsupported even when the map omitted it entirely.
    #[test]
    fn unknown_tip_branch_is_reported_without_a_map_entry() {
        let i = info(vec![], Some(FUTURE), Some(FUTURE));
        let got = unsupported_upgrades(&i);
        assert_eq!(got.len(), 1, "one entry, not one per consensus field");
        assert!(got[0].active);
        assert_eq!(got[0].branch_id, FUTURE);
        assert_eq!(got[0].name, "unknown upgrade");
    }

    /// A pending map entry whose branch ID already rules the next block is promoted to active
    /// severity: the wallet is about to fetch blocks it cannot apply, so "update before height
    /// H" would be stale advice.
    #[test]
    fn next_block_branch_promotes_a_pending_entry_to_active() {
        let i = info(
            vec![upgrade(
                FUTURE,
                "NU-Future",
                4_100_000,
                UpgradeStatus::Pending,
            )],
            Some(KNOWN_NU6),
            Some(FUTURE),
        );
        let got = unsupported_upgrades(&i);
        assert_eq!(got.len(), 1);
        assert!(got[0].active, "imminent activation is active severity");
        assert_eq!(got[0].name, "NU-Future", "the map entry's name is kept");
    }
}
