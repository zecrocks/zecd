//! The zebrad backend: [`ZebraSource`] derives everything the wallet needs directly from a
//! full node's JSON-RPC, removing the lightwalletd hop for self-hosted deployments. Each
//! [`ChainSource`] operation maps onto the same node RPCs lightwalletd itself uses:
//!
//! | operation             | zebrad JSON-RPC                                            |
//! |-----------------------|------------------------------------------------------------|
//! | `latest_block`        | `getblockchaininfo` (height + best hash)                   |
//! | `tree_state`          | `z_gettreestate` (finalState hex → protobuf `TreeState`)   |
//! | `compact_block_range` | `getblock verbosity=0` (raw block, parsed + compacted      |
//! |                       | locally) + `getblock verbosity=1` (`trees` sizes)          |
//! | `subtree_roots`       | `z_getsubtreesbyindex`                                     |
//! | `server_info`         | `getblockchaininfo` (`chain`)                              |
//! | `broadcast_tx`        | `sendrawtransaction`                                       |
//! | `fetch_tx`            | `getrawtransaction verbose=1`                              |
//! | `subscribe_mempool`   | `getrawmempool` + `getrawtransaction`, polled; the stream  |
//! |                       | closes when `getbestblockhash` changes (lightwalletd       |
//! |                       | parity: stream-close is the actor's sync-now signal)       |
//!
//! The full-block→CompactBlock conversion ([`block_to_compact`]) is the part lightwalletd
//! otherwise does for us: parse the raw block (`zcash_primitives::block::Block`), then per
//! transaction extract the trial-decryption fields via librustzcash's own `From` impls
//! (Sapling nullifier/cmu/epk + 52-byte ciphertext prefix; Orchard nullifier/cmx/epk +
//! 52-byte prefix). The commitment-tree sizes lightwalletd puts in `chain_metadata` come
//! from the `trees` field of `getblock verbosity=1`, exactly as lightwalletd obtains them.
//!
//! Scope: a zebra endpoint is for a **local node** - connections are plaintext HTTP with
//! optional cookie/basic auth, and SOCKS proxying is refused at resolve time (see
//! `backend::resolve_all`). Genesis is never requested (no scan range starts there and
//! tree-state requests are clamped to height ≥ 1), which matches `Block::read`'s genesis
//! limitation.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::{connect::HttpConnector, Client as HyperClient};
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use zcash_client_backend::proto::compact_formats as pb;
use zcash_client_backend::proto::service;
use zcash_primitives::block::Block;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{ShieldedProtocol, TxId};

use super::{
    BroadcastOutcome, ChainSource, ChainTip, CompactBlockStream, FetchedTx, MempoolStream,
    ServerInfo, SubtreeRootInfo,
};
use crate::network::ZNetwork;

/// Hard per-request deadline. Every zebra operation is a unary HTTP call to a local node,
/// so unlike the lightwalletd streams there is no long-lived response to keep open; a peer
/// that accepts and then hangs must not stall the sync engine (which, unlike the actor's
/// unary calls, doesn't add its own deadline).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on a JSON-RPC response body. The largest legitimate response is a raw block
/// (≤ 2 MiB consensus) hex-encoded inside a JSON envelope; 64 MiB is comfortably above any
/// of that while still bounding a misbehaving upstream.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// How often the mempool poller re-reads `getrawmempool` / checks for a new block. The
/// lightwalletd stream pushes; polling trades ~this much latency for it.
const MEMPOOL_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Credentials for zebrad's RPC endpoint (`[zebra]` config). A cookie file wins over
/// user/password; both empty means no auth (zebrad with `enable_cookie_auth = false`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZebraAuth {
    pub user: Option<String>,
    pub password: Option<String>,
    /// Path to zebrad's RPC cookie file; re-read on every connect, since zebrad regenerates
    /// it at startup.
    pub cookie: Option<PathBuf>,
}

impl ZebraAuth {
    /// Build the `Authorization` header value, if any. Errors are configuration problems
    /// (unreadable cookie, user without password) and should fail the connect loudly.
    pub fn header(&self) -> anyhow::Result<Option<String>> {
        if let Some(path) = &self.cookie {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("reading zebra rpc cookie {}", path.display()))?;
            let cred = contents.trim();
            if !cred.contains(':') {
                bail!(
                    "zebra rpc cookie {} is not in user:password form",
                    path.display()
                );
            }
            return Ok(Some(basic(cred)));
        }
        match (&self.user, &self.password) {
            (Some(u), Some(p)) => Ok(Some(basic(&format!("{u}:{p}")))),
            (None, None) => Ok(None),
            _ => Err(anyhow!(
                "[zebra] rpc_user and rpc_password must be set together"
            )),
        }
    }
}

fn basic(cred: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(cred)
    )
}

/// A JSON-RPC call failure, split along the trait's error contract: `Rpc` is the node
/// examining the request and refusing it (the connection is healthy); `Transport` is
/// everything else.
#[derive(Debug)]
enum CallError {
    Transport(anyhow::Error),
    Rpc { code: i64, message: String },
}

impl CallError {
    fn transport(e: impl Into<anyhow::Error>) -> Self {
        CallError::Transport(e.into())
    }
    fn into_anyhow(self, method: &str) -> anyhow::Error {
        match self {
            CallError::Transport(e) => e.context(format!("zebra rpc {method}")),
            CallError::Rpc { code, message } => {
                anyhow!("zebra rpc {method} failed ({code}): {message}")
            }
        }
    }
}

/// A cheaply-clonable zebrad JSON-RPC client (hyper pools the underlying connections).
#[derive(Clone)]
pub struct ZebraClient {
    http: HyperClient<HttpConnector, Full<Bytes>>,
    url: hyper::Uri,
    auth_header: Option<String>,
}

impl ZebraClient {
    /// Build a client for `http://host:port/`. The auth header is resolved here (cookie
    /// read once per connect) so a bad credential setup fails at connect time.
    pub fn new(host: &str, port: u16, auth: &ZebraAuth) -> anyhow::Result<ZebraClient> {
        let url: hyper::Uri = format!("http://{host}:{port}/")
            .parse()
            .with_context(|| format!("invalid zebra rpc address {host}:{port}"))?;
        Ok(ZebraClient {
            http: HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new()),
            url,
            auth_header: auth.header()?,
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, CallError> {
        let body = json!({ "jsonrpc": "2.0", "id": "zecd", "method": method, "params": params });
        let mut req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(self.url.clone())
            .header(hyper::header::CONTENT_TYPE, "application/json");
        if let Some(auth) = &self.auth_header {
            req = req.header(hyper::header::AUTHORIZATION, auth.clone());
        }
        let req = req
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(CallError::transport)?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.http.request(req))
            .await
            .map_err(|_| {
                CallError::Transport(anyhow!("zebra rpc timed out after {REQUEST_TIMEOUT:?}"))
            })?
            .map_err(CallError::transport)?;

        // RPC-level failures come back with non-200 statuses but still carry the JSON error
        // envelope (Bitcoin-Core convention), so parse the body regardless of status and
        // fall back to the status code only when there is no envelope to read.
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|e| CallError::Transport(anyhow!("reading zebra rpc response: {e}")))?
            .to_bytes();
        let envelope: Value = serde_json::from_slice(&body).map_err(|e| {
            CallError::Transport(anyhow!(
                "zebra rpc returned non-JSON response (HTTP {status}): {e}"
            ))
        })?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            return Err(CallError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string(),
            });
        }
        if !status.is_success() {
            return Err(CallError::Transport(anyhow!(
                "zebra rpc returned HTTP {status}"
            )));
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `call` + deserialize, for methods where any RPC error is a transport-class failure.
    async fn call_as<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> anyhow::Result<T> {
        let result = self
            .call(method, params)
            .await
            .map_err(|e| e.into_anyhow(method))?;
        serde_json::from_value(result)
            .with_context(|| format!("decoding zebra rpc {method} response"))
    }

    async fn blockchain_info(&self) -> anyhow::Result<BlockchainInfo> {
        self.call_as("getblockchaininfo", json!([])).await
    }

    async fn best_block_hash(&self) -> anyhow::Result<String> {
        self.call_as("getbestblockhash", json!([])).await
    }

    /// Raw block bytes by height (or display-hex hash).
    async fn block_raw(&self, hash_or_height: &str) -> anyhow::Result<Vec<u8>> {
        let hex_str: String = self.call_as("getblock", json!([hash_or_height, 0])).await?;
        hex::decode(hex_str.trim()).context("decoding raw block hex")
    }

    /// The note-commitment-tree sizes after this block, from `getblock verbosity=1`'s
    /// `trees` field - the same place lightwalletd gets `chain_metadata` from. Queried by
    /// hash (not height) so the sizes can't race a reorg against the raw-block fetch.
    async fn block_trees(&self, hash: &str) -> anyhow::Result<(u32, u32)> {
        let verbose: VerboseBlock = self.call_as("getblock", json!([hash, 1])).await?;
        let trees = verbose.trees.unwrap_or_default();
        // A pool that isn't active yet at this block is reported by zebra as an empty object
        // (`"orchard": {}`), i.e. present with no `size`, so a missing size legitimately means
        // 0 here. That makes a *malformed* post-activation response (size omitted when the pool
        // IS active) indistinguishable from the pre-activation case without an activation-height
        // check - see the TODO below; for now both default to 0 as lightwalletd does.
        // TODO(hardening): once validated against a live zebra, error on a missing size for a
        // block at/after the pool's activation height (a hostile/buggy node could otherwise feed
        // a wrong commitment-tree size). Bounded today by the subtree-root sync + the local-node
        // trust model.
        Ok((
            trees.sapling.and_then(|t| t.size).unwrap_or(0),
            trees.orchard.and_then(|t| t.size).unwrap_or(0),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct BlockchainInfo {
    chain: String,
    blocks: u32,
    bestblockhash: String,
}

#[derive(Debug, Deserialize)]
struct VerboseBlock {
    #[serde(default)]
    trees: Option<Trees>,
}

#[derive(Debug, Default, Deserialize)]
struct Trees {
    #[serde(default)]
    sapling: Option<TreeSize>,
    #[serde(default)]
    orchard: Option<TreeSize>,
}

#[derive(Debug, Deserialize)]
struct TreeSize {
    #[serde(default)]
    size: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct TreeStateReply {
    hash: String,
    height: u32,
    time: u32,
    #[serde(default)]
    sapling: Option<PoolTreeState>,
    #[serde(default)]
    orchard: Option<PoolTreeState>,
}

#[derive(Debug, Default, Deserialize)]
struct PoolTreeState {
    #[serde(default)]
    commitments: Option<Commitments>,
}

impl PoolTreeState {
    fn final_state(self) -> String {
        self.commitments
            .and_then(|c| c.final_state)
            .unwrap_or_default()
    }
}

#[derive(Debug, Default, Deserialize)]
struct Commitments {
    #[serde(rename = "finalState", default)]
    final_state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubtreesReply {
    #[serde(default)]
    subtrees: Vec<SubtreeEntry>,
}

#[derive(Debug, Deserialize)]
struct SubtreeEntry {
    root: String,
    end_height: u32,
}

#[derive(Debug, Deserialize)]
struct VerboseTx {
    hex: String,
    #[serde(default)]
    height: Option<i64>,
}

/// A connected zebrad backend.
pub struct ZebraSource {
    client: ZebraClient,
    network: ZNetwork,
    /// zebrad's `getblockchaininfo.chain`, captured at connect, used to fill the protobuf
    /// `TreeState.network` field (informational; nothing in zecd reads it back).
    chain_name: String,
    /// Poll cadence for the synthesized mempool stream; tests shrink this.
    mempool_poll: Duration,
}

impl ZebraSource {
    /// Connect: build the client and verify the node answers (`getblockchaininfo`), which
    /// is the closest analog of the lightwalletd dial. The caller bounds this with its
    /// connect timeout.
    pub async fn connect(
        host: &str,
        port: u16,
        auth: &ZebraAuth,
        network: ZNetwork,
    ) -> anyhow::Result<ZebraSource> {
        let client = ZebraClient::new(host, port, auth)?;
        let info = client.blockchain_info().await?;
        Ok(ZebraSource {
            client,
            network,
            chain_name: info.chain,
            mempool_poll: MEMPOOL_POLL_INTERVAL,
        })
    }

    #[cfg(test)]
    fn with_mempool_poll(mut self, poll: Duration) -> Self {
        self.mempool_poll = poll;
        self
    }
}

impl ChainSource for ZebraSource {
    async fn latest_block(&mut self) -> anyhow::Result<ChainTip> {
        let info = self.client.blockchain_info().await?;
        // The RPC reports the hash as display hex (byte-reversed); the trait contract (and
        // lightwalletd's BlockId) is internal byte order.
        let mut hash = hex::decode(&info.bestblockhash).context("decoding bestblockhash")?;
        hash.reverse();
        Ok(ChainTip {
            height: u64::from(info.blocks),
            hash,
        })
    }

    async fn tree_state(&mut self, height: BlockHeight) -> anyhow::Result<service::TreeState> {
        let reply: TreeStateReply = self
            .client
            .call_as("z_gettreestate", json!([u32::from(height).to_string()]))
            .await?;
        // Identical mapping to lightwalletd's GetTreeState: hash/height/time pass through
        // (hash stays display hex; `to_chain_state` reverses it), and the tree fields are
        // the `commitments.finalState` hex (empty when the pool isn't active yet).
        Ok(service::TreeState {
            network: self.chain_name.clone(),
            height: u64::from(reply.height),
            hash: reply.hash,
            time: reply.time,
            sapling_tree: reply.sapling.unwrap_or_default().final_state(),
            orchard_tree: reply.orchard.unwrap_or_default().final_state(),
        })
    }

    async fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> anyhow::Result<CompactBlockStream> {
        Ok(CompactBlockStream::Zebra(ZebraBlockStream {
            client: self.client.clone(),
            network: self.network,
            next: u32::from(start),
            end: u32::from(end),
        }))
    }

    async fn subtree_roots(
        &mut self,
        protocol: ShieldedProtocol,
    ) -> anyhow::Result<Vec<SubtreeRootInfo>> {
        let pool = match protocol {
            ShieldedProtocol::Sapling => "sapling",
            ShieldedProtocol::Orchard => "orchard",
        };
        // start_index 0, no limit: all completed subtrees (what lightwalletd serves).
        let reply: SubtreesReply = self
            .client
            .call_as("z_getsubtreesbyindex", json!([pool, 0]))
            .await?;
        reply
            .subtrees
            .into_iter()
            .map(|s| {
                Ok(SubtreeRootInfo {
                    // Subtree roots are node hashes, not txids/block hashes: the hex is NOT
                    // byte-reversed (lightwalletd decodes it verbatim too).
                    root_hash: hex::decode(&s.root).context("decoding subtree root hex")?,
                    completing_height: s.end_height,
                })
            })
            .collect()
    }

    async fn server_info(&mut self) -> anyhow::Result<ServerInfo> {
        let info = self.client.blockchain_info().await?;
        Ok(ServerInfo {
            chain_name: info.chain,
        })
    }

    async fn broadcast_tx(&mut self, data: Vec<u8>) -> anyhow::Result<BroadcastOutcome> {
        match self
            .client
            .call("sendrawtransaction", json!([hex::encode(&data)]))
            .await
        {
            Ok(_txid) => Ok(BroadcastOutcome::accepted()),
            // The node examined the tx and refused it: an application-level rejection, not
            // a transport failure (mirrors lightwalletd's SendResponse.error_code != 0).
            Err(CallError::Rpc { code, message }) => Ok(BroadcastOutcome {
                error_code: i32::try_from(code).unwrap_or(i32::MIN),
                error_message: message,
            }),
            Err(e) => Err(e.into_anyhow("sendrawtransaction")),
        }
    }

    async fn fetch_tx(&mut self, txid: TxId) -> anyhow::Result<Option<FetchedTx>> {
        // `TxId`'s Display is the byte-reversed hex the RPC expects.
        let reply = self
            .client
            .call("getrawtransaction", json!([txid.to_string(), 1]))
            .await;
        let verbose: VerboseTx = match reply {
            Ok(v) => serde_json::from_value(v).context("decoding getrawtransaction response")?,
            // -5 (RPC_INVALID_ADDRESS_OR_KEY) is "no such transaction" in both zcashd and
            // zebrad: an application-level miss, the connection stays healthy.
            Err(CallError::Rpc { code: -5, .. }) => return Ok(None),
            Err(CallError::Rpc { message, .. })
                if message.to_lowercase().contains("no such mempool") =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e.into_anyhow("getrawtransaction")),
        };
        let data = hex::decode(verbose.hex.trim()).context("decoding raw transaction hex")?;
        // zebra reports `height: -1` (zcashd omits it) for mempool transactions.
        let mined_height = verbose
            .height
            .filter(|h| *h > 0)
            .and_then(|h| u32::try_from(h).ok());
        Ok(Some(FetchedTx { data, mined_height }))
    }

    async fn subscribe_mempool(&mut self) -> anyhow::Result<MempoolStream> {
        // Baseline tip: the stream synthesizes lightwalletd's close-on-new-block by ending
        // itself once the best hash moves away from this.
        let baseline = self.client.best_block_hash().await?;
        let (tx, rx) = mpsc::channel(64);
        let task = tokio::spawn(poll_mempool(
            self.client.clone(),
            baseline,
            tx,
            self.mempool_poll,
        ));
        Ok(MempoolStream::Zebra(ZebraMempoolStream {
            rx,
            _task: AbortOnDrop(task),
        }))
    }
}

/// Sequentially materializes the compact blocks for one scan range: two RPCs per block
/// (raw bytes by height, then `trees` sizes by the parsed hash), converted locally.
pub struct ZebraBlockStream {
    client: ZebraClient,
    network: ZNetwork,
    next: u32,
    /// Inclusive end height.
    end: u32,
}

impl ZebraBlockStream {
    pub async fn next(&mut self) -> anyhow::Result<Option<pb::CompactBlock>> {
        if self.next > self.end {
            return Ok(None);
        }
        let height = self.next;
        let raw = self.client.block_raw(&height.to_string()).await?;
        let block = Block::read(&raw[..], &self.network)
            .with_context(|| format!("parsing block {height}"))?;
        // The coinbase-claimed height is the only height a raw block carries; a mismatch
        // means the node served something other than what we asked for.
        if block.claimed_height() != BlockHeight::from_u32(height) {
            bail!(
                "zebra served block claiming height {} for requested height {height}",
                u32::from(block.claimed_height()),
            );
        }
        let (sapling_size, orchard_size) = self
            .client
            .block_trees(&block.header().hash().to_string())
            .await?;
        self.next += 1;
        Ok(Some(block_to_compact(&block, sapling_size, orchard_size)))
    }
}

/// Convert a parsed full block into the CompactBlock lightwalletd would serve for it: per
/// transaction, the txid plus the Sapling/Orchard trial-decryption fields (via
/// librustzcash's own `From` impls, which take the 52-byte ciphertext prefixes), and the
/// end-of-block commitment-tree sizes as `chain_metadata`. Like current lightwalletd, every
/// transaction is included (transparent-only ones simply carry no shielded elements; the
/// scanner ignores them) and `index` is the tx's position in the block.
pub fn block_to_compact(block: &Block, sapling_size: u32, orchard_size: u32) -> pb::CompactBlock {
    let header = block.header();
    let vtx = block
        .vtx()
        .iter()
        .enumerate()
        .map(|(index, tx)| pb::CompactTx {
            index: index as u64,
            txid: tx.txid().as_ref().to_vec(),
            fee: 0,
            spends: tx
                .sapling_bundle()
                .map(|b| b.shielded_spends().iter().map(Into::into).collect())
                .unwrap_or_default(),
            outputs: tx
                .sapling_bundle()
                .map(|b| b.shielded_outputs().iter().map(Into::into).collect())
                .unwrap_or_default(),
            actions: tx
                .orchard_bundle()
                .map(|b| b.actions().iter().map(Into::into).collect())
                .unwrap_or_default(),
            vin: vec![],
            vout: vec![],
        })
        .collect();
    pb::CompactBlock {
        proto_version: 0,
        height: u64::from(u32::from(block.claimed_height())),
        hash: header.hash().0.to_vec(),
        prev_hash: header.prev_block.0.to_vec(),
        time: header.time,
        header: vec![],
        vtx,
        chain_metadata: Some(pb::ChainMetadata {
            sapling_commitment_tree_size: sapling_size,
            orchard_commitment_tree_size: orchard_size,
        }),
    }
}

/// The consumer half of the synthesized mempool stream.
pub struct ZebraMempoolStream {
    rx: mpsc::Receiver<anyhow::Result<service::RawTransaction>>,
    /// Aborts the poller when the stream is dropped (e.g. the actor reconnects).
    _task: AbortOnDrop,
}

impl ZebraMempoolStream {
    pub async fn message(&mut self) -> anyhow::Result<Option<service::RawTransaction>> {
        match self.rx.recv().await {
            Some(Ok(raw)) => Ok(Some(raw)),
            Some(Err(e)) => Err(e),
            // Channel closed: the poller saw a new block (or finished after an error it
            // already reported) - lightwalletd's close-on-new-block signal.
            None => Ok(None),
        }
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The mempool poller: yield every current and newly-arriving mempool transaction exactly
/// once, then return (closing the channel) when a new block arrives. Errors are reported
/// once and end the stream - the actor treats that as "drop the subscription" and the next
/// caught-up pass resubscribes.
async fn poll_mempool(
    client: ZebraClient,
    baseline_best_hash: String,
    tx: mpsc::Sender<anyhow::Result<service::RawTransaction>>,
    poll: Duration,
) {
    let mut seen: HashSet<String> = HashSet::new();
    loop {
        let txids: Vec<String> = match client.call_as("getrawmempool", json!([])).await {
            Ok(ids) => ids,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        // Bound `seen` to the current mempool: drop txids that have left it (mined or evicted)
        // so the set can't grow without bound if the tip doesn't advance for a long time. A tx
        // that leaves and later reappears is then re-yielded, which is the correct "fresh
        // arrival to scan" behavior.
        let current: HashSet<String> = txids.iter().cloned().collect();
        seen.retain(|t| current.contains(t));
        for txid in txids {
            if !seen.insert(txid.clone()) {
                continue;
            }
            match client.call("getrawtransaction", json!([txid, 1])).await {
                Ok(v) => {
                    let Ok(verbose) = serde_json::from_value::<VerboseTx>(v) else {
                        continue;
                    };
                    let Ok(data) = hex::decode(verbose.hex.trim()) else {
                        continue;
                    };
                    let raw = service::RawTransaction { data, height: 0 };
                    if tx.send(Ok(raw)).await.is_err() {
                        return; // subscriber dropped the stream
                    }
                }
                // The tx left the mempool between the two calls (mined or evicted): skip only on
                // a genuine "no such transaction". Any other RPC error ends the stream (reported
                // once) rather than being silently swallowed, matching `fetch_tx`.
                Err(CallError::Rpc { code: -5, .. }) => continue,
                Err(CallError::Rpc { message, .. })
                    if message.to_lowercase().contains("no such mempool") =>
                {
                    continue
                }
                Err(e) => {
                    let _ = tx.send(Err(e.into_anyhow("getrawtransaction"))).await;
                    return;
                }
            }
        }
        tokio::time::sleep(poll).await;
        match client.best_block_hash().await {
            // New block: close the stream (the actor's signal to sync immediately).
            Ok(best) if best != baseline_best_hash => return,
            Ok(_) => {}
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};

    /// Real mainnet block 415000 (the `zcash_primitives` test vector): one transparent-only
    /// coinbase transaction, Overwinter era. Ground truth (independent, from block
    /// explorers): hash `0000000001ab37793ce771262b2ffa082519aa3fe891250a1adb43baaf856168`,
    /// prev `00000000037e7ff9f4199871b4ae31e5cf4dd26384f7933ef4d84a9e3bb47452`, time
    /// 1540144808 (2018-10-21 18:00:08 UTC), coinbase txid
    /// `ce93a30a82e4fb43c7a45afcbd97970473a56872ad6ac3bec995fa4bbc733066`.
    const BLOCK_415000_HEX: &str = include_str!("testdata/block_mainnet_415000.hex");
    const BLOCK_415000_HASH: &str =
        "0000000001ab37793ce771262b2ffa082519aa3fe891250a1adb43baaf856168";
    const BLOCK_415000_PREV: &str =
        "00000000037e7ff9f4199871b4ae31e5cf4dd26384f7933ef4d84a9e3bb47452";
    const BLOCK_415000_COINBASE_TXID: &str =
        "ce93a30a82e4fb43c7a45afcbd97970473a56872ad6ac3bec995fa4bbc733066";

    /// Decode a display-order (RPC) hex hash into internal byte order.
    fn internal(display_hex: &str) -> Vec<u8> {
        let mut b = hex::decode(display_hex).unwrap();
        b.reverse();
        b
    }

    /// An in-process zebrad: a single JSON-RPC POST endpoint answering from canned state.
    /// This is the offline test double for every RPC `ZebraSource` issues; the regtest e2e
    /// exercises the same code against a real zebrad.
    struct Fake {
        chain: String,
        blocks: u32,
        best: String,
        /// `getblock` responses keyed by the hash-or-height parameter, per verbosity.
        raw_blocks: HashMap<String, String>,
        verbose_blocks: HashMap<String, Value>,
        treestate: Value,
        subtrees: Value,
        mempool: Vec<String>,
        raw_txs: HashMap<String, Value>,
        /// `Err((code, message))` makes `sendrawtransaction` reject.
        send: Result<String, (i64, String)>,
        /// Authorization header values observed, in order.
        seen_auth: Vec<Option<String>>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                chain: "main".into(),
                blocks: 415000,
                best: BLOCK_415000_HASH.into(),
                raw_blocks: HashMap::new(),
                verbose_blocks: HashMap::new(),
                treestate: Value::Null,
                subtrees: Value::Null,
                mempool: Vec::new(),
                raw_txs: HashMap::new(),
                send: Ok("00".repeat(32)),
                seen_auth: Vec::new(),
            }
        }
    }

    type Shared = Arc<Mutex<Fake>>;

    async fn handler(
        State(state): State<Shared>,
        headers: axum::http::HeaderMap,
        Json(req): Json<Value>,
    ) -> Json<Value> {
        let mut fake = state.lock().unwrap();
        fake.seen_auth.push(
            headers
                .get(axum::http::header::AUTHORIZATION)
                .map(|v| v.to_str().unwrap().to_string()),
        );
        let method = req["method"].as_str().unwrap_or_default().to_string();
        let params = req["params"].clone();
        let reply = |v: Value| Json(json!({ "result": v, "error": null, "id": "zecd" }));
        let err = |code: i64, msg: &str| {
            Json(json!({
                "result": null,
                "error": { "code": code, "message": msg },
                "id": "zecd"
            }))
        };
        match method.as_str() {
            "getblockchaininfo" => reply(json!({
                "chain": fake.chain,
                "blocks": fake.blocks,
                "bestblockhash": fake.best,
            })),
            "getbestblockhash" => reply(json!(fake.best)),
            "getblock" => {
                let key = params[0].as_str().unwrap_or_default().to_string();
                let verbosity = params[1].as_i64().unwrap_or(1);
                if verbosity == 0 {
                    match fake.raw_blocks.get(&key) {
                        Some(hex) => reply(json!(hex)),
                        None => err(-8, "Block not found"),
                    }
                } else {
                    match fake.verbose_blocks.get(&key) {
                        Some(v) => reply(v.clone()),
                        None => err(-8, "Block not found"),
                    }
                }
            }
            "z_gettreestate" => reply(fake.treestate.clone()),
            "z_getsubtreesbyindex" => reply(fake.subtrees.clone()),
            "getrawmempool" => reply(json!(fake.mempool)),
            "getrawtransaction" => {
                let txid = params[0].as_str().unwrap_or_default();
                match fake.raw_txs.get(txid) {
                    Some(v) => reply(v.clone()),
                    None => err(-5, "No such mempool or main chain transaction"),
                }
            }
            "sendrawtransaction" => match &fake.send {
                Ok(txid) => reply(json!(txid)),
                Err((code, msg)) => err(*code, msg),
            },
            other => err(-32601, &format!("Method not found: {other}")),
        }
    }

    async fn serve(fake: Shared) -> SocketAddr {
        let app = Router::new().route("/", post(handler)).with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    async fn source_for(fake: Shared) -> ZebraSource {
        let addr = serve(fake).await;
        ZebraSource::connect(
            &addr.ip().to_string(),
            addr.port(),
            &ZebraAuth::default(),
            ZNetwork::Main,
        )
        .await
        .expect("connect to fake zebrad")
    }

    #[tokio::test]
    async fn latest_block_and_server_info_from_getblockchaininfo() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        let mut src = source_for(fake).await;

        let tip = src.latest_block().await.unwrap();
        assert_eq!(tip.height, 415000);
        // The RPC hash is display hex; the trait contract is internal byte order.
        assert_eq!(tip.hash, internal(BLOCK_415000_HASH));

        let info = src.server_info().await.unwrap();
        assert_eq!(info.chain_name, "main");
    }

    #[tokio::test]
    async fn basic_auth_and_cookie_auth_send_the_right_header() {
        // user/password.
        let fake = Arc::new(Mutex::new(Fake::new()));
        let addr = serve(fake.clone()).await;
        let auth = ZebraAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };
        let mut src =
            ZebraSource::connect(&addr.ip().to_string(), addr.port(), &auth, ZNetwork::Main)
                .await
                .unwrap();
        src.latest_block().await.unwrap();
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("u:p")
        );
        assert!(fake
            .lock()
            .unwrap()
            .seen_auth
            .iter()
            .all(|a| a.as_deref() == Some(expected.as_str())));

        // Cookie file (zebrad regenerates it at startup; we read it at connect).
        let dir = tempfile::tempdir().unwrap();
        let cookie = dir.path().join(".cookie");
        std::fs::write(&cookie, "__cookie__:s3cret\n").unwrap();
        let fake2 = Arc::new(Mutex::new(Fake::new()));
        let addr2 = serve(fake2.clone()).await;
        let auth = ZebraAuth {
            user: None,
            password: None,
            cookie: Some(cookie),
        };
        let mut src =
            ZebraSource::connect(&addr2.ip().to_string(), addr2.port(), &auth, ZNetwork::Main)
                .await
                .unwrap();
        src.latest_block().await.unwrap();
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("__cookie__:s3cret")
        );
        assert!(fake2
            .lock()
            .unwrap()
            .seen_auth
            .iter()
            .all(|a| a.as_deref() == Some(expected.as_str())));

        // A user without a password (or vice versa) is a configuration error.
        assert!(ZebraAuth {
            user: Some("u".into()),
            password: None,
            cookie: None
        }
        .header()
        .is_err());
        // A malformed cookie (no colon) is refused rather than sent as garbage.
        let bad = dir.path().join("bad-cookie");
        std::fs::write(&bad, "nocolon\n").unwrap();
        assert!(ZebraAuth {
            user: None,
            password: None,
            cookie: Some(bad)
        }
        .header()
        .is_err());
    }

    #[tokio::test]
    async fn tree_state_maps_z_gettreestate_like_lightwalletd() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        fake.lock().unwrap().treestate = json!({
            "hash": BLOCK_415000_HASH,
            "height": 415000,
            "time": 1540144808,
            // Pools report finalState hex under commitments; pre-activation pools omit it.
            "sapling": { "commitments": {} },
            "orchard": {},
        });
        let mut src = source_for(fake).await;
        let ts = src.tree_state(BlockHeight::from_u32(415000)).await.unwrap();
        assert_eq!(ts.height, 415000);
        assert_eq!(
            ts.hash, BLOCK_415000_HASH,
            "hash passes through as display hex"
        );
        assert_eq!(ts.time, 1540144808);
        assert_eq!(
            ts.sapling_tree, "",
            "absent finalState maps to the empty string"
        );
        assert_eq!(ts.orchard_tree, "");
        // The protobuf converts exactly like a lightwalletd-served TreeState: empty tree
        // strings parse as empty frontiers and the hash round-trips into internal order.
        let cs = ts.to_chain_state().expect("converts to ChainState");
        assert_eq!(u32::from(cs.block_height()), 415000);
        assert_eq!(cs.block_hash().0.to_vec(), internal(BLOCK_415000_HASH));

        // Non-empty finalState hex must pass through verbatim (lightwalletd does not
        // re-encode it; the consumer decodes).
        let fake = Arc::new(Mutex::new(Fake::new()));
        fake.lock().unwrap().treestate = json!({
            "hash": BLOCK_415000_HASH,
            "height": 415000,
            "time": 1540144808,
            "sapling": { "commitments": { "finalState": "0123ab" } },
            "orchard": { "commitments": { "finalState": "cdef45" } },
        });
        let mut src = source_for(fake).await;
        let ts = src.tree_state(BlockHeight::from_u32(415000)).await.unwrap();
        assert_eq!(ts.sapling_tree, "0123ab");
        assert_eq!(ts.orchard_tree, "cdef45");
    }

    #[tokio::test]
    async fn subtree_roots_decode_hex_without_reversal() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        fake.lock().unwrap().subtrees = json!({
            "pool": "orchard",
            "start_index": 0,
            "subtrees": [
                { "root": "0a0b0c", "end_height": 5 },
                { "root": "0d0e0f", "end_height": 9 },
            ],
        });
        let mut src = source_for(fake).await;
        let roots = src.subtree_roots(ShieldedProtocol::Orchard).await.unwrap();
        assert_eq!(roots.len(), 2);
        // Subtree roots are node hashes: decoded verbatim, never byte-reversed.
        assert_eq!(roots[0].root_hash, vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(roots[0].completing_height, 5);
        assert_eq!(roots[1].root_hash, vec![0x0d, 0x0e, 0x0f]);
        assert_eq!(roots[1].completing_height, 9);
    }

    #[tokio::test]
    async fn broadcast_maps_acceptance_and_rejection() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        let mut src = source_for(fake.clone()).await;
        let outcome = src.broadcast_tx(vec![0xab; 8]).await.unwrap();
        assert!(outcome.is_accepted());

        // An explicit node rejection is an application-level outcome (Ok), carrying the
        // node's code and message - never a transport error.
        fake.lock().unwrap().send = Err((-26, "tx unpaid action limit exceeded".into()));
        let outcome = src.broadcast_tx(vec![0xab; 8]).await.unwrap();
        assert_eq!(outcome.error_code, -26);
        assert_eq!(outcome.error_message, "tx unpaid action limit exceeded");
        assert!(!outcome.is_accepted());
    }

    #[tokio::test]
    async fn fetch_tx_returns_bytes_height_and_not_found() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        let txid = TxId::from_bytes([0x11; 32]);
        // `TxId`'s Display is the reversed hex the RPC speaks.
        fake.lock().unwrap().raw_txs.insert(
            txid.to_string(),
            json!({ "hex": "deadbeef", "height": 415000 }),
        );
        let mempool_txid = TxId::from_bytes([0x22; 32]);
        fake.lock().unwrap().raw_txs.insert(
            mempool_txid.to_string(),
            json!({ "hex": "cafe", "height": -1 }),
        );
        let mut src = source_for(fake).await;

        let mined = src.fetch_tx(txid).await.unwrap().expect("known txid");
        assert_eq!(mined.data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(mined.mined_height, Some(415000));

        // zebra reports height -1 for mempool transactions: bytes, but no mined height.
        let unmined = src
            .fetch_tx(mempool_txid)
            .await
            .unwrap()
            .expect("mempool txid");
        assert_eq!(unmined.data, vec![0xca, 0xfe]);
        assert_eq!(unmined.mined_height, None);

        // -5 is an application-level miss (Ok(None)), not a transport failure.
        assert!(src
            .fetch_tx(TxId::from_bytes([0x33; 32]))
            .await
            .unwrap()
            .is_none());
    }

    /// The block-range path end to end against a real mainnet block: raw bytes are fetched
    /// by height, parsed, cross-checked against the claimed height, and compacted with the
    /// tree sizes from `getblock verbosity=1` - every assertion is against independently
    /// known values (block explorer data), not against our own conversion code.
    #[tokio::test]
    async fn block_range_compacts_a_real_block() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        {
            let mut f = fake.lock().unwrap();
            f.raw_blocks
                .insert("415000".into(), BLOCK_415000_HEX.trim().into());
            // The verbose (trees) lookup is by the parsed block's hash, not by height.
            f.verbose_blocks.insert(
                BLOCK_415000_HASH.into(),
                json!({ "hash": BLOCK_415000_HASH, "trees": { "sapling": { "size": 7 }, "orchard": {} } }),
            );
        }
        let mut src = source_for(fake).await;
        let mut stream = src
            .compact_block_range(BlockHeight::from_u32(415000), BlockHeight::from_u32(415000))
            .await
            .unwrap();

        let cb = stream.next().await.unwrap().expect("one block");
        assert_eq!(cb.height, 415000);
        assert_eq!(
            cb.hash,
            internal(BLOCK_415000_HASH),
            "hash in internal byte order"
        );
        assert_eq!(cb.prev_hash, internal(BLOCK_415000_PREV));
        assert_eq!(cb.time, 1540144808);
        assert_eq!(
            cb.vtx.len(),
            1,
            "every tx is included (lightwalletd parity)"
        );
        let tx = &cb.vtx[0];
        assert_eq!(tx.index, 0);
        assert_eq!(
            tx.txid,
            internal(BLOCK_415000_COINBASE_TXID),
            "txid in protocol order"
        );
        assert!(tx.spends.is_empty() && tx.outputs.is_empty() && tx.actions.is_empty());
        let meta = cb.chain_metadata.as_ref().expect("chain metadata");
        assert_eq!(meta.sapling_commitment_tree_size, 7);
        assert_eq!(
            meta.orchard_commitment_tree_size, 0,
            "absent pool size maps to 0"
        );

        assert!(stream.next().await.unwrap().is_none(), "range exhausted");
    }

    /// A node serving the wrong block for a requested height (or garbage) must fail the
    /// stream, not feed the scanner mislabeled data.
    #[tokio::test]
    async fn block_range_rejects_height_mismatch_and_garbage() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        {
            let mut f = fake.lock().unwrap();
            // Block 415000's bytes served for height 5: the coinbase-claimed height exposes it.
            f.raw_blocks
                .insert("5".into(), BLOCK_415000_HEX.trim().into());
            f.raw_blocks.insert("6".into(), "00ff00ff".into());
        }
        let mut src = source_for(fake).await;

        let mut stream = src
            .compact_block_range(BlockHeight::from_u32(5), BlockHeight::from_u32(5))
            .await
            .unwrap();
        let err = stream.next().await.expect_err("height mismatch must error");
        assert!(
            err.to_string().contains("claiming height 415000"),
            "got: {err:#}"
        );

        let mut stream = src
            .compact_block_range(BlockHeight::from_u32(6), BlockHeight::from_u32(6))
            .await
            .unwrap();
        assert!(
            stream.next().await.is_err(),
            "unparseable block bytes must error"
        );
    }

    /// The synthesized mempool stream preserves lightwalletd's semantics: every current and
    /// newly-arriving tx is yielded exactly once, and the stream closes (yields `None`)
    /// when a new block arrives.
    #[tokio::test]
    async fn mempool_stream_yields_dedupes_and_closes_on_new_block() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        {
            let mut f = fake.lock().unwrap();
            f.mempool = vec!["aa".repeat(32)];
            f.raw_txs
                .insert("aa".repeat(32), json!({ "hex": "0101", "height": -1 }));
        }
        let mut src = source_for(fake.clone())
            .await
            .with_mempool_poll(Duration::from_millis(20));
        let mut stream = match src.subscribe_mempool().await.unwrap() {
            MempoolStream::Zebra(s) => s,
            MempoolStream::Lwd(_) => unreachable!(),
        };

        // The current mempool is streamed first.
        let first = stream.message().await.unwrap().expect("first mempool tx");
        assert_eq!(first.data, vec![0x01, 0x01]);
        assert_eq!(
            first.height, 0,
            "mempool txs report height 0 (lightwalletd parity)"
        );

        // A tx that arrives later is picked up by a subsequent poll; the first tx is not
        // re-yielded.
        {
            let mut f = fake.lock().unwrap();
            f.mempool = vec!["aa".repeat(32), "bb".repeat(32)];
            f.raw_txs
                .insert("bb".repeat(32), json!({ "hex": "0202", "height": -1 }));
        }
        let second = stream.message().await.unwrap().expect("newly-arriving tx");
        assert_eq!(second.data, vec![0x02, 0x02]);

        // A new block closes the stream - the actor's sync-now signal.
        fake.lock().unwrap().best = "11".repeat(32);
        assert!(
            stream.message().await.unwrap().is_none(),
            "stream must close once the best block hash moves"
        );
    }
}
