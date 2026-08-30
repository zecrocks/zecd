//! The lightwalletd backend: [`LwdSource`] maps each [`ChainSource`] operation onto the
//! `CompactTxStreamer` gRPC call the actor/sync engine were originally written against.
//! Pure adapter - no behavior beyond translating types and encoding lightwalletd's
//! application-level outcomes (tx rejected, txid unknown) into the trait's `Ok` shapes.
//!
//! Transparent data comes in two flavors depending on the server generation, probed once at
//! connect via `GetLightdInfo.lightwalletProtocolVersion`:
//!  * a **versioned-protocol** server (zcash/lightwalletd master and later releases) accepts
//!    `poolTypes` on `BlockRange` and returns each block's transparent inputs/outputs inside
//!    the compact blocks - so `include_transparent` works exactly like the zebra backend's
//!    per-block extraction ([`Self::block_scan_covers_transparent`] is `true`);
//!  * a **legacy** server (≤ v0.4.x, today's public fleet) omits transparent data from compact
//!    blocks entirely; the wallet falls back to address-index queries (`GetAddressUtxos` +
//!    `GetTaddressTxids`) - the standard librustzcash lightclient mechanism.

use std::sync::Arc;

use anyhow::anyhow;
use prost::Message;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tonic::transport::Channel;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    self, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{ShieldedPool, TxId};

use super::{
    AbortOnDrop, BroadcastOutcome, ChainSource, ChainTip, CompactBlockStream, FetchedTx,
    MempoolStream, ServerInfo, SubtreeRootInfo, TransparentSpend, TransparentUtxo, TxEvidence,
};

/// A connected lightwalletd client.
///
/// `Clone` because [`crate::chain::hub::ChainHub`] hands every consumer its own handle onto one
/// shared connection: a tonic `Channel` is a cheap handle onto one multiplexed HTTP/2 connection,
/// so cloned sources share it rather than dialing again.
#[derive(Clone)]
pub struct LwdSource {
    client: CompactTxStreamerClient<Channel>,
    /// Whether the server speaks the versioned lightwallet-protocol (`poolTypes` on
    /// `BlockRange`, transparent + ironwood data in compact blocks). Probed once at connect;
    /// the protocol's own rule is that clients MUST verify capability before requesting
    /// non-default pool types.
    pool_types_capable: bool,
}

impl LwdSource {
    /// Wrap a freshly dialed channel, probing the server's protocol generation (one
    /// `GetLightdInfo` round-trip - which also serves as the connect-time liveness check).
    pub async fn connect(channel: Channel, assume_capable: bool) -> anyhow::Result<Self> {
        let mut client = CompactTxStreamerClient::new(channel);
        let info = client
            .get_lightd_info(service::Empty {})
            .await?
            .into_inner();
        // Legacy servers predate the field and report "". So does every released lightwalletd
        // to date - the reference implementation never populates it - which is why the operator
        // can assert the capability out of band ([backend]
        // assume_transparent_in_compact_blocks).
        let advertised = !info.lightwallet_protocol_version.is_empty();
        let pool_types_capable = advertised || assume_capable;
        tracing::info!(
            vendor = %info.vendor,
            version = %info.version,
            chain = %info.chain_name,
            protocol_version = %info.lightwallet_protocol_version,
            transparent_in_compact_blocks = pool_types_capable,
            "lightwalletd server info{}",
            match (advertised, assume_capable) {
                (false, true) =>
                    " (capability assumed via [backend] assume_transparent_in_compact_blocks)",
                _ => "",
            },
        );
        if !advertised && assume_capable {
            tracing::warn!(
                "[backend] assume_transparent_in_compact_blocks overrides the capability probe: \
                 this server does not advertise a lightwallet protocol version. If it does not \
                 in fact serve transparent data in compact blocks, transparent receives will \
                 never be discovered"
            );
        }
        Ok(LwdSource {
            client,
            pool_types_capable,
        })
    }

    /// Test-only constructor for a client whose capability is known a priori.
    #[cfg(test)]
    pub fn with_capability(
        client: CompactTxStreamerClient<Channel>,
        pool_types_capable: bool,
    ) -> Self {
        LwdSource {
            client,
            pool_types_capable,
        }
    }
}

impl ChainSource for LwdSource {
    async fn latest_block(&mut self) -> anyhow::Result<ChainTip> {
        let block_id = self
            .client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner();
        // lightwalletd reports the block hash in internal byte order already.
        Ok(ChainTip {
            height: block_id.height,
            hash: block_id.hash,
        })
    }

    async fn tree_state(&mut self, height: BlockHeight) -> anyhow::Result<service::TreeState> {
        let tree_state = self
            .client
            .get_tree_state(service::BlockId {
                height: height.into(),
                hash: vec![],
            })
            .await?
            .into_inner();
        // A mismatched height would corrupt the wallet's birthday/anchor bookkeeping; treat it
        // as a transport-class failure (same guard as the zebra backend).
        if tree_state.height != u64::from(height) {
            return Err(anyhow!(
                "tree state height mismatch: requested {height}, got {}",
                tree_state.height
            ));
        }
        Ok(tree_state)
    }

    async fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
        include_transparent: bool,
    ) -> anyhow::Result<CompactBlockStream> {
        // Only request non-default pool types from a server that advertised the versioned
        // protocol - the protocol requires clients to verify capability first, and a legacy
        // server may reject (or silently misinterpret) the field.
        let extract_transparent = include_transparent && self.pool_types_capable;
        let pool_types = if extract_transparent {
            vec![
                service::PoolType::Transparent as i32,
                service::PoolType::Sapling as i32,
                service::PoolType::Orchard as i32,
                service::PoolType::Ironwood as i32,
            ]
        } else {
            // Default = legacy behavior: shielded pools only.
            vec![]
        };
        let range = service::BlockRange {
            start: Some(service::BlockId {
                height: start.into(),
                hash: vec![],
            }),
            end: Some(service::BlockId {
                height: end.into(),
                hash: vec![],
            }),
            pool_types,
        };
        let stream = self.client.get_block_range(range).await?.into_inner();
        let (rx, task) = spawn_block_reader(stream, BLOCK_BUFFER_BYTES);

        Ok(CompactBlockStream::Lwd(LwdBlockStream {
            rx,
            extract_transparent,
            _task: task,
        }))
    }

    async fn subtree_roots(
        &mut self,
        protocol: ShieldedPool,
    ) -> anyhow::Result<Vec<SubtreeRootInfo>> {
        let mut request = service::GetSubtreeRootsArg::default();
        request.set_shielded_protocol(match protocol {
            ShieldedPool::Sapling => service::ShieldedProtocol::Sapling,
            ShieldedPool::Orchard => service::ShieldedProtocol::Orchard,
            ShieldedPool::Ironwood => service::ShieldedProtocol::Ironwood,
        });
        let mut stream = self.client.get_subtree_roots(request).await?.into_inner();
        let mut roots = Vec::new();
        while let Some(root) = stream.message().await? {
            roots.push(SubtreeRootInfo {
                root_hash: root.root_hash,
                completing_height: u32::try_from(root.completing_block_height)
                    .map_err(|_| anyhow!("subtree root completing height out of range"))?,
            });
        }
        Ok(roots)
    }

    async fn server_info(&mut self) -> anyhow::Result<ServerInfo> {
        let info = self
            .client
            .get_lightd_info(service::Empty {})
            .await?
            .into_inner();
        Ok(ServerInfo {
            chain_name: info.chain_name,
            // `GetLightdInfo` has no upgrades map, so the outdated-build detector's map half
            // has nothing to inspect in light mode. It does report the branch ruling the tip
            // (`consensusBranchId`, bare hex like `getblockchaininfo`'s), which feeds the
            // detector's belt check: an unrecognized branch there still surfaces as an active
            // unsupported upgrade.
            upgrades: Vec::new(),
            tip_branch_id: u32::from_str_radix(info.consensus_branch_id.trim(), 16).ok(),
            next_block_branch_id: None,
        })
    }

    async fn broadcast_tx(&mut self, data: Vec<u8>) -> anyhow::Result<BroadcastOutcome> {
        let raw = service::RawTransaction {
            data,
            ..Default::default()
        };
        let response = self.client.send_transaction(raw).await?.into_inner();
        Ok(BroadcastOutcome {
            error_code: response.error_code,
            error_message: response.error_message,
        })
    }

    async fn fetch_tx(&mut self, txid: TxId) -> anyhow::Result<Option<FetchedTx>> {
        // The `TxFilter` hash is the txid's internal bytes (per zcash-devtool's enhance).
        let filter = service::TxFilter {
            hash: txid.as_ref().to_vec(),
            ..Default::default()
        };
        let raw = match self.client.get_transaction(filter).await {
            Ok(r) => r.into_inner(),
            // The upstream looked up the txid and doesn't know it: an application-level
            // miss, not a transport failure - keep the (healthy) client.
            Err(status) if is_tx_not_found(&status) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(if raw.data.is_empty() {
            None
        } else {
            Some(FetchedTx {
                data: raw.data,
                mined_height: mined_height_from_raw(raw.height),
            })
        })
    }

    async fn transparent_tx_evidence(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> anyhow::Result<Vec<TxEvidence>> {
        // `GetTaddressTxids` takes ONE address per call (unlike zebra's batched
        // `getaddresstxids`), with an inclusive block range, and streams the **full raw
        // transactions** - which we pass through as `TxEvidence::Raw` so the caller can store
        // them without a per-txid re-fetch. Mempool transactions are excluded by the protocol.
        let mut evidence = Vec::new();
        for address in addresses {
            let filter = service::TransparentAddressBlockFilter {
                address,
                range: Some(service::BlockRange {
                    start: Some(service::BlockId {
                        height: u64::from(start),
                        hash: vec![],
                    }),
                    end: Some(service::BlockId {
                        height: u64::from(end),
                        hash: vec![],
                    }),
                    pool_types: vec![],
                }),
            };
            let mut stream = self.client.get_taddress_txids(filter).await?.into_inner();
            while let Some(raw) = stream.message().await? {
                if raw.data.is_empty() {
                    continue;
                }
                evidence.push(TxEvidence::Raw(FetchedTx {
                    mined_height: mined_height_from_raw(raw.height),
                    data: raw.data,
                }));
            }
        }
        Ok(evidence)
    }

    fn block_scan_covers_transparent(&self) -> bool {
        self.pool_types_capable
    }

    async fn subscribe_mempool(&mut self) -> anyhow::Result<MempoolStream> {
        // `GetMempoolStream`'s response headers may not be flushed until the server has a
        // first message to send: a legacy lightwalletd over an *empty* mempool leaves the
        // call pending until a tx arrives or a new block closes the stream, so awaiting the
        // setup inline would park the single-writer actor for the whole unary timeout on
        // every caught-up pass (starving queued sends - this stalled real CI sends by ~60s).
        // Run the call on a detached forwarder instead (tonic clients clone cheaply - the
        // underlying channel is shared) and hand back a channel-backed stream immediately;
        // whenever the server finally responds, txs/closes flow through the channel.
        let mut client = self.client.clone();
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(async move {
            let mut stream = match client.get_mempool_stream(service::Empty::default()).await {
                Ok(resp) => resp.into_inner(),
                Err(e) => {
                    let _ = tx.send(Err(anyhow::Error::from(e))).await;
                    return;
                }
            };
            loop {
                match stream.message().await {
                    Ok(Some(raw)) => {
                        if tx.send(Ok(raw)).await.is_err() {
                            return; // subscriber dropped the stream
                        }
                    }
                    // Server closed the stream (new block): dropping the sender closes the
                    // channel, which the subscriber reads as `Ok(None)`.
                    Ok(None) => return,
                    Err(e) => {
                        let _ = tx.send(Err(anyhow::Error::from(e))).await;
                        return;
                    }
                }
            }
        });
        Ok(MempoolStream::Lwd(LwdMempoolStream {
            rx,
            _task: AbortOnDrop(task),
        }))
    }
}

/// A channel-backed `GetMempoolStream` subscription: the gRPC call and its message loop run
/// on a detached task (see [`ChainSource::subscribe_mempool`] on [`LwdSource`] for why the
/// setup await cannot run inline), and this end just drains the channel.
pub struct LwdMempoolStream {
    rx: mpsc::Receiver<anyhow::Result<service::RawTransaction>>,
    /// Aborts the forwarder when the stream is dropped (e.g. the actor reconnects).
    _task: AbortOnDrop,
}

impl LwdMempoolStream {
    pub async fn message(&mut self) -> anyhow::Result<Option<service::RawTransaction>> {
        match self.rx.recv().await {
            Some(Ok(raw)) => Ok(Some(raw)),
            Some(Err(e)) => Err(e),
            // Channel closed: the server ended the stream (its close-on-new-block signal) or
            // the forwarder finished after an error it already reported.
            None => Ok(None),
        }
    }
}

/// One buffered block plus the buffer permit it holds, or the stream error that ended the
/// range. See [`spawn_block_reader`].
type BufferedBlock = anyhow::Result<(CompactBlock, OwnedSemaphorePermit)>;

/// Drain `stream` on a detached task, handing blocks to the consumer through a buffer bounded
/// at `buffer_bytes` of serialized compact-block data, rather than letting the sync engine's
/// per-block work (the transparent matching, `encode_to_vec`, and the block-cache
/// `File::create` + `write_all`) run between stream polls.
///
/// h2 (0.4.13+) budgets the framing overhead of received-but-unpolled sub-256-byte DATA
/// frames as a DoS protection, replenishing the budget only as the application polls frames
/// off the connection. A mostly empty compact block - the norm on testnet, and on any chain
/// below its shielded activity - is one such tiny frame, so whenever the disk is slower than
/// the network (a virus scanner opening every new block file, a CI runner on datacenter
/// bandwidth) a few hundred frames pile up inside h2 and it kills its own healthy connection
/// with GOAWAY ENHANCE_YOUR_CALM (`too_many_data_frames`). The failure is self-perpetuating:
/// the range restarts at the same height on the next pass and dies the same way, so the
/// wallet never advances past its birthday, while the unary tip probe keeps succeeding and
/// makes the server look perfectly healthy.
///
/// Draining eagerly keeps h2's receive buffer close to empty so the budget replenishes as
/// fast as frames arrive. The bound is on **bytes**, not messages: the dangerous case is many
/// tiny blocks, and a message count high enough to help there would hold far too much memory
/// on a range of large ones. A whole scan batch of small blocks fits well under the bound, so
/// the reader never stalls in the case that matters; large blocks may backpressure it, but
/// those replenish the budget by themselves and are safe to read slowly. It is not a complete
/// defense on its own - the budget is charged as h2's connection task *parses* frames off the
/// socket, so a fast enough burst can exhaust it before this task is scheduled at all - which
/// is why `sync::engine` also resumes the range after a shed.
///
/// Errors are reported *through* the channel rather than out of band, so the consumer still
/// sees every block that arrived before the failure. That is what lets the sync engine resume
/// a load-shed range from the last block it actually wrote instead of restarting it.
fn spawn_block_reader<S>(
    stream: S,
    buffer_bytes: usize,
) -> (mpsc::UnboundedReceiver<BufferedBlock>, AbortOnDrop)
where
    S: futures_util::Stream<Item = Result<CompactBlock, tonic::Status>> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(buffer_bytes));
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        futures_util::pin_mut!(stream);
        while let Some(next) = futures_util::StreamExt::next(&mut stream).await {
            let block = match next {
                Ok(block) => block,
                Err(e) => {
                    let _ = tx.send(Err(anyhow::Error::from(e)));
                    return;
                }
            };
            // Charge the block's serialized size, clamped so an oversized block takes the
            // whole buffer instead of deadlocking on an unsatisfiable request, and so a
            // zero-length one still costs something.
            let cost = block.encoded_len().clamp(1, buffer_bytes) as u32;
            let Ok(permit) = permits.clone().acquire_many_owned(cost).await else {
                return; // the semaphore is never closed; nothing to do if it were
            };
            // The permit rides with the block and is released once the consumer takes it out
            // of the channel.
            if tx.send(Ok((block, permit))).is_err() {
                return; // consumer dropped the stream
            }
        }
        // End of range: dropping the sender closes the channel, which the consumer reads as
        // `Ok(None)`.
    });
    (rx, AbortOnDrop(task))
}

/// Upper bound on compact-block bytes buffered between the `GetBlockRange` reader task and
/// the consumer in [`LwdBlockStream`]. See [`spawn_block_reader`] for why the bound is in
/// bytes, and why it needs to exist at all.
const BLOCK_BUFFER_BYTES: usize = 32 * 1024 * 1024;

/// An in-order compact-block stream from `GetBlockRange`, optionally harvesting each block's
/// transparent outputs (versioned-protocol servers only - see the module doc).
///
/// Channel-backed: the gRPC stream is drained by a detached task so the consumer's per-block
/// work never leaves received frames sitting unpolled inside h2 (see [`spawn_block_reader`]).
/// This end just takes blocks off the channel and does the transparent extraction, which is
/// pure CPU over an in-memory block.
pub struct LwdBlockStream {
    rx: mpsc::UnboundedReceiver<BufferedBlock>,
    extract_transparent: bool,
    /// Aborts the reader when the stream is dropped (the range finished early, or the sync
    /// engine is restarting the range after a load shed).
    _task: AbortOnDrop,
}

impl LwdBlockStream {
    #[allow(clippy::type_complexity)]
    pub async fn next(
        &mut self,
    ) -> anyhow::Result<Option<(CompactBlock, Vec<TransparentUtxo>, Vec<TransparentSpend>)>> {
        // Channel closed: the reader reached the end of the range, or finished after an error
        // it already delivered below.
        let Some(next) = self.rx.recv().await else {
            return Ok(None);
        };
        // Dropping the permit here returns this block's bytes to the buffer. The consumer
        // holds one block beyond the bound while it works, which is the point: that work no
        // longer happens between stream polls.
        let (block, _permit) = next?;
        let (transparent, spends) = if self.extract_transparent {
            (
                block_transparent_outputs(&block),
                block_transparent_spends(&block),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        Ok(Some((block, transparent, spends)))
    }
}

/// Harvest every transparent input in a versioned-protocol compact block, as spend candidates
/// for the wallet's unspent-outpoint matcher. `CompactTxIn` carries the full outpoint
/// (`prevoutTxid` + `prevoutIndex`), which is all the matcher needs - so a light-mode wallet
/// detects spends of its own UTXOs from the same compact block it already fetched, exactly as
/// the zebra backend does from the full block.
///
/// A coinbase transaction's null prevout spends nothing; lightwalletd omits `vin` for it, and a
/// stray entry could never match a real wallet outpoint anyway.
fn block_transparent_spends(block: &CompactBlock) -> Vec<TransparentSpend> {
    let Ok(height) = u32::try_from(block.height) else {
        return Vec::new();
    };
    let mut spends = Vec::new();
    for tx in &block.vtx {
        let Ok(txid_bytes) = <[u8; 32]>::try_from(tx.txid.as_slice()) else {
            continue;
        };
        let spending_txid = TxId::from_bytes(txid_bytes);
        for input in &tx.vin {
            let Ok(prevout_bytes) = <[u8; 32]>::try_from(input.prevout_txid.as_slice()) else {
                continue;
            };
            spends.push(TransparentSpend {
                prevout_txid: TxId::from_bytes(prevout_bytes),
                prevout_index: input.prevout_index,
                spending_txid,
                height,
            });
        }
    }
    spends
}

/// Harvest every transparent output in a versioned-protocol compact block. `CompactTx.vout`
/// mirrors the transaction's full `vout` array (the `TxOut`s carry no explicit index), so the
/// output index is positional. The height is the block's own height (these are mined outputs
/// by construction).
fn block_transparent_outputs(block: &CompactBlock) -> Vec<TransparentUtxo> {
    let height = u32::try_from(block.height).ok();
    let mut outputs = Vec::new();
    for tx in &block.vtx {
        let Ok(txid_bytes) = <[u8; 32]>::try_from(tx.txid.as_slice()) else {
            // A malformed txid poisons only this tx's outputs; the shielded scan has its own
            // integrity checks.
            continue;
        };
        let txid = TxId::from_bytes(txid_bytes);
        for (index, out) in tx.vout.iter().enumerate() {
            outputs.push(TransparentUtxo {
                txid,
                index: index as u32,
                value_zat: out.value,
                script: out.script_pub_key.clone(),
                height,
                // A compact tx is not the full transaction, so the coinbase tagging the zebra
                // block scan does (storing the parsed coinbase tx alongside a matched output)
                // has no source here; a coinbase receive found via a versioned-protocol block
                // scan is recorded without its maturity marker until the enhancement pass
                // stores the full transaction.
                coinbase_tx: None,
            });
        }
    }
    outputs
}

/// Interpret a `RawTransaction.height` as a mined block height. lightwalletd reports the
/// mined height there for a confirmed tx, but a mempool (unmined) tx carries `0` or `-1`
/// (the latter encoded into the unsigned field as `u64::MAX`) - neither is a real height.
/// So only a positive, in-`u32`-range value counts as mined; everything else is "unmined".
fn mined_height_from_raw(height: u64) -> Option<u32> {
    u32::try_from(height).ok().filter(|h| *h > 0)
}

/// True when a `GetTransaction` error status means the node simply does not know the txid -
/// an application-level miss the RPC layer reports as -5, not a transport failure worth
/// dropping the connection over. lightwalletd proxies the backing node's message through:
/// zcashd says "No such mempool transaction" / "No such mempool or blockchain transaction"
/// (with -txindex) or, historically, "No information available about transaction"; zebrad
/// says "No such mempool or main chain transaction".
fn is_tx_not_found(status: &tonic::Status) -> bool {
    if status.code() == tonic::Code::NotFound {
        return true;
    }
    let msg = status.message().to_lowercase();
    msg.contains("no such mempool") || msg.contains("no information available about transaction")
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::proto::compact_formats::{CompactBlock, CompactTx, TxOut};

    use super::{
        block_transparent_outputs, is_tx_not_found, mined_height_from_raw, spawn_block_reader,
    };

    /// `fetch_tx`'s mempool-vs-mined rule: only a positive in-range `height` is a mined
    /// height. A mempool tx (0, or -1 encoded as `u64::MAX`) and an out-of-range value are
    /// "unmined" - this is what keeps a 0-conf mempool payment reported with no confirmations.
    #[test]
    fn mined_height_distinguishes_mempool_from_confirmed() {
        assert_eq!(mined_height_from_raw(0), None, "0 is the mempool sentinel");
        assert_eq!(
            mined_height_from_raw(u64::MAX),
            None,
            "-1 (encoded as u64::MAX) is the other mempool sentinel"
        );
        assert_eq!(mined_height_from_raw(1), Some(1));
        assert_eq!(mined_height_from_raw(2_500_000), Some(2_500_000));
        assert_eq!(
            mined_height_from_raw(u32::MAX as u64),
            Some(u32::MAX),
            "the largest representable block height is still mined"
        );
        assert_eq!(
            mined_height_from_raw(u32::MAX as u64 + 1),
            None,
            "out of u32 range is not a real height"
        );
    }

    #[test]
    fn tx_not_found_statuses_are_misses_not_failures() {
        for msg in [
            "No such mempool transaction. Use -txindex to enable blockchain transaction queries.",
            "No such mempool or blockchain transaction",
            "No such mempool or main chain transaction",
            "-5: No such mempool or main chain transaction",
            "No information available about transaction",
        ] {
            assert!(
                is_tx_not_found(&tonic::Status::unknown(msg)),
                "{msg:?} must classify as not-found"
            );
        }
        assert!(is_tx_not_found(&tonic::Status::not_found("anything")));
        // Transport-class failures must still drop the client.
        assert!(!is_tx_not_found(&tonic::Status::unavailable(
            "connection refused"
        )));
        assert!(!is_tx_not_found(&tonic::Status::deadline_exceeded(
            "timed out"
        )));
    }

    /// The versioned-protocol transparent harvest: `vout` indexes are positional, values and
    /// scripts pass through, the height is the block's, and a malformed txid drops only that
    /// tx's outputs.
    #[test]
    fn block_transparent_outputs_are_positional_and_block_high() {
        let block = CompactBlock {
            height: 1234,
            vtx: vec![
                CompactTx {
                    txid: vec![0x11; 32],
                    vout: vec![
                        TxOut {
                            value: 5000,
                            script_pub_key: vec![0xAA],
                        },
                        TxOut {
                            value: 7000,
                            script_pub_key: vec![0xBB],
                        },
                    ],
                    ..Default::default()
                },
                CompactTx {
                    txid: vec![0x22; 4], // malformed: not 32 bytes
                    vout: vec![TxOut {
                        value: 9000,
                        script_pub_key: vec![0xCC],
                    }],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let outs = block_transparent_outputs(&block);
        assert_eq!(outs.len(), 2, "the malformed-txid tx contributes nothing");
        assert_eq!(outs[0].txid.as_ref(), &[0x11; 32]);
        assert_eq!(outs[0].index, 0);
        assert_eq!(outs[0].value_zat, 5000);
        assert_eq!(outs[0].script, vec![0xAA]);
        assert_eq!(outs[0].height, Some(1234));
        assert_eq!(outs[1].index, 1, "vout index is positional");
        assert_eq!(outs[1].value_zat, 7000);
    }

    /// A compact block whose serialized size is predictable, so the buffer-bound test can do
    /// arithmetic on it.
    fn sized_block(height: u64) -> CompactBlock {
        CompactBlock {
            height,
            ..Default::default()
        }
    }

    /// The reader must deliver every block, in order, and then close the channel. This is the
    /// baseline the sync engine's `while let Some(..) = stream.next()` loop depends on.
    #[tokio::test]
    async fn the_reader_delivers_every_block_in_order_then_closes() {
        let blocks: Vec<Result<CompactBlock, tonic::Status>> =
            (1..=5).map(|h| Ok(sized_block(h))).collect();
        let (mut rx, _task) =
            spawn_block_reader(futures_util::stream::iter(blocks), 32 * 1024 * 1024);

        let mut heights = vec![];
        while let Some(next) = rx.recv().await {
            let (block, _permit) = next.expect("no error in this stream");
            heights.push(block.height);
        }
        assert_eq!(heights, vec![1, 2, 3, 4, 5]);
    }

    /// A stream error must arrive *after* the blocks that preceded it, not instead of them.
    /// The sync engine's load-shed resume is built on exactly this: the blocks already
    /// delivered are already on disk, so the retry resumes past them instead of restarting
    /// the range and hitting the same wall.
    #[tokio::test]
    async fn blocks_received_before_a_stream_error_are_still_delivered() {
        let items: Vec<Result<CompactBlock, tonic::Status>> = vec![
            Ok(sized_block(1)),
            Ok(sized_block(2)),
            Err(tonic::Status::resource_exhausted(
                "h2 protocol error: error reading a body from connection",
            )),
            Ok(sized_block(3)),
        ];
        let (mut rx, _task) =
            spawn_block_reader(futures_util::stream::iter(items), 32 * 1024 * 1024);

        let mut heights = vec![];
        let mut err = None;
        while let Some(next) = rx.recv().await {
            match next {
                Ok((block, _permit)) => heights.push(block.height),
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        assert_eq!(heights, vec![1, 2], "everything before the error survives");
        assert!(err.is_some(), "the error itself reaches the consumer");
    }

    /// The buffer is bounded by **bytes**, and the bound actually holds the reader back: with
    /// room for one block, a second cannot be buffered until the first is taken out. This is
    /// what keeps a range of large blocks from being pulled wholly into memory, while a range
    /// of tiny ones (the case that caused the load shed) streams freely.
    #[tokio::test]
    async fn the_buffer_bound_is_in_bytes_and_holds_the_reader() {
        let one = prost::Message::encoded_len(&sized_block(1));
        let blocks: Vec<Result<CompactBlock, tonic::Status>> =
            (1..=3).map(|h| Ok(sized_block(h))).collect();
        // Room for exactly one block at a time.
        let (mut rx, _task) = spawn_block_reader(futures_util::stream::iter(blocks), one);

        let (first, first_permit) = rx.recv().await.unwrap().unwrap();
        assert_eq!(first.height, 1);
        // Give the reader every chance to run: it must still be parked on the semaphore.
        tokio::task::yield_now().await;
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "the second block must wait for the first one's bytes to be returned"
        );

        // Returning the first block's bytes unblocks the reader.
        drop(first_permit);
        let (second, _permit) = rx.recv().await.unwrap().unwrap();
        assert_eq!(second.height, 2);
    }

    /// A block larger than the whole buffer must still get through (clamped to the full
    /// budget) rather than deadlocking on a permit request that can never be satisfied.
    #[tokio::test]
    async fn a_block_larger_than_the_buffer_still_gets_through() {
        let block = CompactBlock {
            height: 7,
            hash: vec![0xAB; 4096],
            ..Default::default()
        };
        assert!(prost::Message::encoded_len(&block) > 8);
        let (mut rx, _task) = spawn_block_reader(futures_util::stream::iter(vec![Ok(block)]), 8);
        let (got, _permit) = rx.recv().await.unwrap().unwrap();
        assert_eq!(got.height, 7);
    }
}
