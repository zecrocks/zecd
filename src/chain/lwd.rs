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

use anyhow::anyhow;
use tokio::sync::mpsc;
use tonic::transport::Channel;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::{
    self, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{ShieldedPool, TxId};

use super::{
    AbortOnDrop, BroadcastOutcome, ChainSource, ChainTip, CompactBlockStream, FetchedTx,
    MempoolStream, ServerInfo, SubtreeRootInfo, TransparentUtxo, TxEvidence,
};

/// Addresses per `GetAddressUtxos` call. Educated guess against public servers' request-size
/// and row limits (~35 B/address ⇒ ~35 KB/request); verified against testnet.zec.rocks in the
/// `#[ignore]` network tests in `backend.rs`.
pub const UTXO_ADDR_CHUNK: usize = 1_000;

/// A connected lightwalletd client.
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
    pub async fn connect(channel: Channel) -> anyhow::Result<Self> {
        let mut client = CompactTxStreamerClient::new(channel);
        let info = client
            .get_lightd_info(service::Empty {})
            .await?
            .into_inner();
        // Legacy servers predate the field and report "".
        let pool_types_capable = !info.lightwallet_protocol_version.is_empty();
        tracing::info!(
            "lightwalletd: {} {} chain={} protocol_version={:?} (transparent-in-compact-blocks: {})",
            info.vendor,
            info.version,
            info.chain_name,
            info.lightwallet_protocol_version,
            pool_types_capable,
        );
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
        Ok(CompactBlockStream::Lwd(LwdBlockStream {
            stream,
            extract_transparent,
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

    async fn get_address_utxos(
        &mut self,
        addresses: Vec<String>,
        start: u32,
    ) -> anyhow::Result<Vec<TransparentUtxo>> {
        // Chunked so a large exposed-address set can't exceed server request limits. The reply
        // `txid` is already internal byte order (librustzcash's `refresh_utxos` uses it as-is).
        let mut out = Vec::new();
        for chunk in addresses.chunks(UTXO_ADDR_CHUNK) {
            let arg = service::GetAddressUtxosArg {
                addresses: chunk.to_vec(),
                start_height: u64::from(start),
                max_entries: 0,
            };
            let reply = self.client.get_address_utxos(arg).await?.into_inner();
            for utxo in reply.address_utxos {
                let txid_bytes: [u8; 32] = utxo
                    .txid
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("GetAddressUtxos txid is not 32 bytes"))?;
                out.push(TransparentUtxo {
                    txid: TxId::from_bytes(txid_bytes),
                    index: u32::try_from(utxo.index)
                        .map_err(|_| anyhow!("GetAddressUtxos output index out of range"))?,
                    value_zat: u64::try_from(utxo.value_zat)
                        .map_err(|_| anyhow!("GetAddressUtxos value out of range"))?,
                    script: utxo.script,
                    height: Some(
                        u32::try_from(utxo.height)
                            .ok()
                            .filter(|h| *h > 0)
                            .ok_or_else(|| anyhow!("GetAddressUtxos height out of range"))?,
                    ),
                });
            }
        }
        Ok(out)
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

/// An in-order compact-block stream from `GetBlockRange`, optionally harvesting each block's
/// transparent outputs (versioned-protocol servers only - see the module doc).
pub struct LwdBlockStream {
    stream: tonic::Streaming<CompactBlock>,
    extract_transparent: bool,
}

impl LwdBlockStream {
    pub async fn next(&mut self) -> anyhow::Result<Option<(CompactBlock, Vec<TransparentUtxo>)>> {
        match self.stream.message().await? {
            None => Ok(None),
            Some(block) => {
                let transparent = if self.extract_transparent {
                    block_transparent_outputs(&block)
                } else {
                    Vec::new()
                };
                Ok(Some((block, transparent)))
            }
        }
    }
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

    use super::{block_transparent_outputs, is_tx_not_found, mined_height_from_raw};

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
}
