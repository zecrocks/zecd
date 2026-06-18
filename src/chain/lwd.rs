//! The lightwalletd backend: [`LwdSource`] maps each [`ChainSource`] operation onto the
//! `CompactTxStreamer` gRPC call the actor/sync engine were originally written against.
//! Pure adapter - no behavior beyond translating types and encoding lightwalletd's
//! application-level outcomes (tx rejected, txid unknown) into the trait's `Ok` shapes.

use anyhow::anyhow;
use tonic::transport::Channel;
use zcash_client_backend::proto::service::{
    self, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{ShieldedProtocol, TxId};

use super::{
    BroadcastOutcome, ChainSource, ChainTip, CompactBlockStream, FetchedTx, MempoolStream,
    ServerInfo, SubtreeRootInfo,
};

/// A connected lightwalletd client.
pub struct LwdSource {
    client: CompactTxStreamerClient<Channel>,
}

impl LwdSource {
    pub fn new(client: CompactTxStreamerClient<Channel>) -> Self {
        LwdSource { client }
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
            .await?;
        Ok(tree_state.into_inner())
    }

    async fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> anyhow::Result<CompactBlockStream> {
        let range = service::BlockRange {
            start: Some(service::BlockId {
                height: start.into(),
                hash: vec![],
            }),
            end: Some(service::BlockId {
                height: end.into(),
                hash: vec![],
            }),
            pool_types: Default::default(),
        };
        let stream = self.client.get_block_range(range).await?.into_inner();
        Ok(CompactBlockStream::Lwd(stream))
    }

    async fn subtree_roots(
        &mut self,
        protocol: ShieldedProtocol,
    ) -> anyhow::Result<Vec<SubtreeRootInfo>> {
        let mut request = service::GetSubtreeRootsArg::default();
        request.set_shielded_protocol(match protocol {
            ShieldedProtocol::Sapling => service::ShieldedProtocol::Sapling,
            ShieldedProtocol::Orchard => service::ShieldedProtocol::Orchard,
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
            // lightwalletd reports the mined height in `height`; mempool transactions carry
            // 0 or -1 (encoded as u64), neither of which is a real mined height here.
            let mined_height = u32::try_from(raw.height).ok().filter(|h| *h > 0);
            Some(FetchedTx {
                data: raw.data,
                mined_height,
            })
        })
    }

    async fn subscribe_mempool(&mut self) -> anyhow::Result<MempoolStream> {
        let stream = self
            .client
            .get_mempool_stream(service::Empty::default())
            .await?
            .into_inner();
        Ok(MempoolStream::Lwd(stream))
    }
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
    use super::is_tx_not_found;

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
}
