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
//! optional cookie/basic auth. Because the auth header would otherwise cross the network in
//! cleartext, [`ZebraClient::new`] gates credentialed connections behind a locality check (see
//! [`host_is_local`] / [`CleartextPolicy`]): loopback and - by default - private/LAN ranges are
//! allowed, but a credentialed connect to a globally-routable host is refused unless the operator
//! opts in via `[backend] allow_remote_cleartext`. Genesis is never requested (no scan range
//! starts there and tree-state requests are clamped to height ≥ 1), which matches `Block::read`'s
//! genesis limitation.

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

/// Parse a display-hex txid (the byte-reversed form the RPC returns) into a [`TxId`] (internal
/// byte order). The inverse of `TxId`'s `Display`.
fn parse_display_txid(s: &str) -> anyhow::Result<TxId> {
    let mut bytes = hex::decode(s.trim()).context("decoding txid hex")?;
    if bytes.len() != 32 {
        bail!("txid is not 32 bytes: {s:?}");
    }
    bytes.reverse();
    let arr: [u8; 32] = bytes.try_into().expect("length checked above");
    Ok(TxId::from_bytes(arr))
}

/// Stand-in `code` for a JSON-RPC error envelope that carries no usable numeric `code`
/// (missing, non-integer, or an explicit `0`). `error_code == 0` is the success sentinel
/// shared by `BroadcastOutcome` and the JSON-RPC success path, so a code-less error must
/// never be parsed as `0` - otherwise a proxy/load-balancer error body without a JSON-RPC
/// code would be indistinguishable from acceptance. `-1` mirrors Bitcoin Core's
/// `RPC_MISC_ERROR` ("unspecified error").
const RPC_ERROR_UNSPECIFIED_CODE: i64 = -1;

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

/// Policy for the plaintext zebra connection's cleartext-credential gate. The zebra RPC is
/// plaintext HTTP, so putting the `Authorization` header on the wire to a host off the local
/// machine risks leaking spend-authority credentials to an eavesdropper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleartextPolicy {
    /// Treat private / non-globally-routable addresses (RFC1918 `10/172.16/192.168`, link-local,
    /// CGNAT `100.64/10`, IPv6 unique-local `fc00::/7` and link-local `fe80::/10`) as "local", so
    /// a credentialed connect to a container/LAN zebra is allowed without an override. Default
    /// `true` (matches the self-hosted `zebra → zecd` Docker/LAN norm); set `false` for a strict
    /// loopback-only posture. `[backend] rfc1918_is_local`.
    pub rfc1918_is_local: bool,
    /// Allow credentials over cleartext to *any* host, including globally-routable ones - the
    /// escape hatch when the hop is secured out-of-band (SSH/WireGuard tunnel, private overlay).
    /// Default `false`. `[backend] allow_remote_cleartext`.
    pub allow_remote_cleartext: bool,
}

impl Default for CleartextPolicy {
    fn default() -> Self {
        CleartextPolicy {
            rfc1918_is_local: true,
            allow_remote_cleartext: false,
        }
    }
}

/// Parse `host` as an IP literal, accepting an IPv6 literal in URL bracket form (`[::1]`) as
/// well as bare (`::1`). Returns `None` for a hostname (no DNS lookup - the gate fails closed).
fn parse_host_ip(host: &str) -> Option<std::net::IpAddr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse().ok()
}

/// Is `host` a loopback address (an IP literal that `is_loopback()`, or the name `localhost`)?
/// Hostnames other than `localhost` are treated as non-loopback without a DNS lookup.
fn host_is_loopback(host: &str) -> bool {
    match parse_host_ip(host) {
        Some(ip) => ip.is_loopback(),
        None => host.eq_ignore_ascii_case("localhost"),
    }
}

/// Does `host` sit on the local machine or a private / non-globally-routable network, keeping the
/// plaintext zebra connection off the public internet? Loopback and `localhost` always qualify;
/// private ranges qualify only when `rfc1918_is_local` is set (see [`CleartextPolicy`]). A
/// globally-routable host never qualifies, so credentials there would cross the internet in the
/// clear - that is what the gate refuses. A hostname other than `localhost` is treated as
/// non-local (no DNS lookup - fail closed).
fn host_is_local(host: &str, rfc1918_is_local: bool) -> bool {
    match parse_host_ip(host) {
        Some(ip) => ip.is_loopback() || (rfc1918_is_local && ip_is_private_network(ip)),
        None => host.eq_ignore_ascii_case("localhost"),
    }
}

/// Is `ip` in a private / non-globally-routable range (as opposed to loopback, handled by the
/// caller, or a globally-routable public address)?
fn ip_is_private_network(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => ipv4_is_private_network(v4),
        // An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) inherits the mapped v4's class.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => ipv4_is_private_network(mapped),
            None => {
                let seg0 = v6.segments()[0];
                (seg0 & 0xfe00) == 0xfc00 // unique local fc00::/7
                    || (seg0 & 0xffc0) == 0xfe80 // link-local fe80::/10
            }
        },
    }
}

fn ipv4_is_private_network(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_private()      // RFC1918 10/8, 172.16/12, 192.168/16
        || ip.is_link_local() // 169.254/16
        // CGNAT 100.64.0.0/10 (RFC 6598) - non-globally-routable, not covered by is_private().
        || (a == 100 && (64..=127).contains(&b))
}

impl ZebraClient {
    /// Build a client for `http://host:port/`. The auth header is resolved here (cookie
    /// read once per connect) so a bad credential setup fails at connect time.
    ///
    /// Cleartext-credential gate: the connection is plaintext HTTP (a zebra endpoint is a local
    /// node by design), so sending RPC credentials to a host off the local machine would leak
    /// them. When credentials are configured for a host that isn't [`host_is_local`] under
    /// `policy`, we refuse the connect unless `policy.allow_remote_cleartext` is set. Private/LAN
    /// ranges count as local by default (`policy.rfc1918_is_local`); loopback always does.
    pub fn new(
        host: &str,
        port: u16,
        auth: &ZebraAuth,
        policy: CleartextPolicy,
    ) -> anyhow::Result<ZebraClient> {
        let url: hyper::Uri = format!("http://{host}:{port}/")
            .parse()
            .with_context(|| format!("invalid zebra rpc address {host}:{port}"))?;
        let auth_header = auth.header()?;
        if auth_header.is_some()
            && !host_is_local(host, policy.rfc1918_is_local)
            && !policy.allow_remote_cleartext
        {
            bail!(
                "refusing to send zebra RPC credentials in cleartext to the globally-routable \
                 host '{host}': the zebra connection is plaintext HTTP, so the Authorization \
                 header would cross the public internet in the clear. Point zecd at a loopback or \
                 private-network zebra (127.0.0.1/localhost, an RFC1918/container address), tunnel \
                 the RPC port over SSH/WireGuard and use the local end, or set `[backend] \
                 allow_remote_cleartext = true` if the hop is already secured."
            );
        }
        if !host_is_loopback(host) {
            tracing::warn!(
                host,
                "zebra endpoint is non-loopback: JSON-RPC traffic is plaintext HTTP"
            );
        }
        Ok(ZebraClient {
            http: HyperClient::builder(TokioExecutor::new()).build(HttpConnector::new()),
            url,
            auth_header,
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

        // One deadline covers the whole round-trip - sending the request, reading the
        // response headers, *and* draining the body. Timing out only `http.request` leaves a
        // header-then-stall upstream free to wedge the body read (`Limited::collect`) forever,
        // which would freeze the sync-batch calls this client serves.
        let (status, body) = tokio::time::timeout(REQUEST_TIMEOUT, async {
            let response = self.http.request(req).await.map_err(CallError::transport)?;
            // RPC-level failures come back with non-200 statuses but still carry the JSON error
            // envelope (Bitcoin-Core convention), so parse the body regardless of status and
            // fall back to the status code only when there is no envelope to read.
            let status = response.status();
            let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                .collect()
                .await
                .map_err(|e| CallError::Transport(anyhow!("reading zebra rpc response: {e}")))?
                .to_bytes();
            Ok::<_, CallError>((status, body))
        })
        .await
        .map_err(|_| {
            CallError::Transport(anyhow!("zebra rpc timed out after {REQUEST_TIMEOUT:?}"))
        })??;

        let envelope: Value = serde_json::from_slice(&body).map_err(|e| {
            CallError::Transport(anyhow!(
                "zebra rpc returned non-JSON response (HTTP {status}): {e}"
            ))
        })?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            // An error envelope is never a success. Keep its `code` away from the `0`
            // acceptance sentinel: a missing, non-integer, or explicit-zero code becomes
            // RPC_ERROR_UNSPECIFIED_CODE, so only an actual zebra success can reach
            // `BroadcastOutcome::is_accepted()`.
            let code = match err.get("code").and_then(Value::as_i64) {
                Some(0) | None => RPC_ERROR_UNSPECIFIED_CODE,
                Some(code) => code,
            };
            return Err(CallError::Rpc {
                code,
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
        policy: CleartextPolicy,
    ) -> anyhow::Result<ZebraSource> {
        let client = ZebraClient::new(host, port, auth, policy)?;
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
        // The birthday anchor is derived from this height (`AccountBirthday::from_treestate`),
        // and the scanner asserts the chain state sits exactly one block below the scan range,
        // so a wrong height silently corrupts the anchor and later panics the scanner. Reject a
        // mismatch as a transport error here (mirrors the raw-block `claimed_height` guard).
        if reply.height != u32::from(height) {
            bail!(
                "zebra served tree state for height {} but height {} was requested",
                reply.height,
                u32::from(height),
            );
        }
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
        include_transparent: bool,
    ) -> anyhow::Result<CompactBlockStream> {
        Ok(CompactBlockStream::Zebra(ZebraBlockStream {
            client: self.client.clone(),
            network: self.network,
            next: u32::from(start),
            end: u32::from(end),
            include_transparent,
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

    async fn transparent_txids(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> anyhow::Result<Vec<TxId>> {
        // zcashd/zebra `getaddresstxids` takes an object param (with a batch of addresses) and
        // returns display-hex txids in chain order. Valid-but-unseen addresses yield `[]`; an error
        // is transport/application and propagates (dropping the client).
        let params = json!([{ "addresses": addresses, "start": start, "end": end }]);
        tracing::debug!(
            "getaddresstxids req addrs={} start={start} end={end}",
            addresses.len()
        );
        let hexes: Vec<String> = self
            .client
            .call_as("getaddresstxids", params)
            .await
            .context("getaddresstxids")?;
        tracing::debug!("getaddresstxids resp -> {} txid(s)", hexes.len());
        let mut out = Vec::with_capacity(hexes.len());
        for h in hexes {
            out.push(parse_display_txid(&h)?);
        }
        Ok(out)
    }

    async fn get_address_utxos(
        &mut self,
        addresses: Vec<String>,
    ) -> anyhow::Result<Vec<super::TransparentUtxo>> {
        // zcashd/zebra `getaddressutxos` takes `{ addresses, chainInfo }` and returns every
        // currently-unspent output paying those addresses (no height filter). `txid` is big-endian
        // (display) hex; `outputIndex`/`satoshis`/`height` are numeric; `script` is hex. An error is
        // transport/application and propagates (dropping the client).
        #[derive(serde::Deserialize)]
        struct Entry {
            txid: String,
            #[serde(rename = "outputIndex")]
            output_index: u32,
            script: String,
            satoshis: u64,
            height: u32,
        }
        let params = json!([{ "addresses": addresses, "chainInfo": false }]);
        tracing::debug!("getaddressutxos req addrs={}", addresses.len());
        let entries: Vec<Entry> = self
            .client
            .call_as("getaddressutxos", params)
            .await
            .context("getaddressutxos")?;
        tracing::debug!("getaddressutxos resp -> {} utxo(s)", entries.len());
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            out.push(super::TransparentUtxo {
                txid: parse_display_txid(&e.txid)?,
                index: e.output_index,
                value_zat: e.satoshis,
                script: hex::decode(&e.script).context("getaddressutxos script hex")?,
                height: Some(e.height),
            });
        }
        Ok(out)
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
    /// Extract each block's transparent outputs alongside its compact block (the wallet's
    /// transparent receive-discovery path). Off for shielded-only wallets so the extraction is
    /// skipped entirely.
    include_transparent: bool,
}

impl ZebraBlockStream {
    pub async fn next(
        &mut self,
    ) -> anyhow::Result<Option<(pb::CompactBlock, Vec<crate::chain::TransparentUtxo>)>> {
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
        // The scanner's per-block transaction index is a 16-bit integer, so more than
        // `u16::MAX` transactions overflows it and panics librustzcash. A real block can't
        // hold that many (non-consensus), so this only guards a malicious or buggy upstream;
        // reject it as a transport error before `block_to_compact` feeds the scanner.
        if block.vtx().len() > usize::from(u16::MAX) {
            bail!(
                "zebra served block {height} with {} transactions, exceeding the {} the scanner supports",
                block.vtx().len(),
                u16::MAX,
            );
        }
        let (sapling_size, orchard_size) = self
            .client
            .block_trees(&block.header().hash().to_string())
            .await?;
        // The raw block was already fetched and parsed for the shielded compact block, so
        // harvesting its transparent outputs here is free (no extra request). The matcher
        // filters to the wallet's addresses; we just surface every output.
        let transparent = if self.include_transparent {
            block_transparent_outputs(&block, height)
        } else {
            Vec::new()
        };
        self.next += 1;
        Ok(Some((
            block_to_compact(&block, sapling_size, orchard_size),
            transparent,
        )))
    }
}

/// Every transparent output in `block`, tagged with the mining `height`, as
/// [`crate::chain::TransparentUtxo`]s. The wallet matches these against its own transparent
/// addresses to discover receives - compact blocks omit transparent I/O, and librustzcash's
/// `decrypt_and_store` only records shielded outputs, so this is the receive-discovery source.
fn block_transparent_outputs(block: &Block, height: u32) -> Vec<crate::chain::TransparentUtxo> {
    let mut out = Vec::new();
    for tx in block.vtx() {
        let Some(bundle) = tx.transparent_bundle() else {
            continue;
        };
        let txid = tx.txid();
        for (index, txout) in bundle.vout.iter().enumerate() {
            out.push(crate::chain::TransparentUtxo {
                txid,
                index: index as u32,
                value_zat: u64::from(txout.value()),
                script: txout.script_pubkey().0 .0.clone(),
                height: Some(height),
            });
        }
    }
    out
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

    #[test]
    fn host_is_loopback_classifies_local_and_remote() {
        // Loopback IP literals (v4 whole /8, v6, and URL-bracketed v6) and the name `localhost`.
        for h in [
            "127.0.0.1",
            "127.5.6.7",
            "::1",
            "[::1]",
            "localhost",
            "LocalHost",
        ] {
            assert!(host_is_loopback(h), "{h} should be loopback");
        }
        // Anything routable, or a hostname other than `localhost`, is treated as remote.
        for h in [
            "10.0.0.5",
            "192.168.1.2",
            "0.0.0.0",
            "zebra.internal",
            "example.com",
        ] {
            assert!(!host_is_loopback(h), "{h} should be non-loopback");
        }
    }

    #[test]
    fn host_is_local_classifies_private_and_public() {
        // Loopback + private/non-routable ranges count as local when rfc1918_is_local is on.
        for h in [
            "127.0.0.1",
            "localhost",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "172.18.0.2", // a typical Docker user-bridge address
            "192.168.1.2",
            "169.254.7.7", // link-local
            "100.64.0.1",  // CGNAT (RFC 6598)
            "::1",
            "[fc00::1]",       // IPv6 unique-local
            "fe80::1",         // IPv6 link-local
            "::ffff:10.0.0.5", // IPv4-mapped private v6
        ] {
            assert!(host_is_local(h, true), "{h} should be local");
        }
        // Globally-routable hosts, and hostnames other than `localhost`, are never local.
        for h in [
            "203.0.113.5", // TEST-NET-3, stands in for a public IP
            "8.8.8.8",
            "172.32.0.1",   // just outside the 172.16/12 block
            "100.128.0.1",  // just outside CGNAT 100.64/10
            "2606:4700::1", // public v6
            "zebra.internal",
            "example.com",
        ] {
            assert!(!host_is_local(h, true), "{h} should be non-local");
        }
        // With rfc1918_is_local off, only loopback stays local - private ranges are treated as
        // remote (the strict posture).
        assert!(host_is_local("127.0.0.1", false));
        assert!(host_is_local("localhost", false));
        assert!(!host_is_local("10.0.0.5", false));
        assert!(!host_is_local("192.168.1.2", false));
    }

    fn creds() -> ZebraAuth {
        ZebraAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        }
    }

    /// Default policy: private ranges are local, no remote override.
    fn default_policy() -> CleartextPolicy {
        CleartextPolicy::default()
    }

    #[test]
    fn client_refuses_cleartext_credentials_to_public_host() {
        let err = match ZebraClient::new("203.0.113.5", 8234, &creds(), default_policy()) {
            Ok(_) => panic!("credentialed public connect must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("cleartext"),
            "message should explain why: {err}"
        );
        assert!(
            err.contains("allow_remote_cleartext"),
            "message should name the override: {err}"
        );
    }

    #[test]
    fn client_allows_credentials_to_loopback_and_private_hosts() {
        // Loopback never leaves the machine; private/LAN ranges are allowed by default.
        for h in [
            "127.0.0.1",
            "localhost",
            "10.0.0.5",
            "172.18.0.2",
            "192.168.1.2",
        ] {
            assert!(
                ZebraClient::new(h, 8234, &creds(), default_policy()).is_ok(),
                "{h} should be allowed under the default policy"
            );
        }
    }

    #[test]
    fn client_refuses_private_host_under_strict_loopback_policy() {
        // rfc1918_is_local = false tightens the gate to loopback-only.
        let strict = CleartextPolicy {
            rfc1918_is_local: false,
            allow_remote_cleartext: false,
        };
        assert!(ZebraClient::new("10.0.0.5", 8234, &creds(), strict).is_err());
        assert!(ZebraClient::new("127.0.0.1", 8234, &creds(), strict).is_ok());
    }

    #[test]
    fn client_allows_credentials_to_public_host_when_opted_in() {
        let allow = CleartextPolicy {
            rfc1918_is_local: true,
            allow_remote_cleartext: true,
        };
        assert!(
            ZebraClient::new("203.0.113.5", 8234, &creds(), allow).is_ok(),
            "explicit allow_remote_cleartext override"
        );
    }

    #[test]
    fn client_allows_unauthenticated_public_connect() {
        // No credentials to leak, so the gate does not apply (traffic is still public chain data).
        assert!(
            ZebraClient::new("203.0.113.5", 8234, &ZebraAuth::default(), default_policy()).is_ok(),
            "no-auth remote connect is allowed"
        );
    }

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
        /// `getaddresstxids` responses keyed by transparent address → display-hex txids.
        addr_txids: HashMap<String, Vec<String>>,
        /// `getaddressutxos` responses keyed by transparent address → UTXO objects
        /// (`{txid, outputIndex, script, satoshis, height}`).
        addr_utxos: HashMap<String, Vec<Value>>,
        /// `Err((code, message))` makes `sendrawtransaction` reject.
        send: Result<String, (i64, String)>,
        /// When set, `sendrawtransaction` returns this exact `error` object verbatim,
        /// overriding `send`. Lets a test inject a malformed envelope (e.g. one with no
        /// numeric `code`, as a fronting proxy might emit).
        send_error_object: Option<Value>,
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
                addr_txids: HashMap::new(),
                addr_utxos: HashMap::new(),
                send: Ok("00".repeat(32)),
                send_error_object: None,
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
            "getaddresstxids" => {
                // Param is an object `{ "addresses": [...], "start": N, "end": M }`.
                let arg = &params[0];
                let addrs = arg["addresses"].as_array().cloned().unwrap_or_default();
                let txids: Vec<String> = addrs
                    .iter()
                    .filter_map(|a| a.as_str())
                    .flat_map(|a| fake.addr_txids.get(a).cloned().unwrap_or_default())
                    .collect();
                reply(json!(txids))
            }
            "getaddressutxos" => {
                // Param is `{ "addresses": [...], "chainInfo": bool }`; returns the union of the
                // configured UTXO objects across the requested addresses.
                let addrs = params[0]["addresses"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let utxos: Vec<Value> = addrs
                    .iter()
                    .filter_map(|a| a.as_str())
                    .flat_map(|a| fake.addr_utxos.get(a).cloned().unwrap_or_default())
                    .collect();
                reply(json!(utxos))
            }
            "sendrawtransaction" => match (&fake.send_error_object, &fake.send) {
                (Some(error), _) => Json(json!({
                    "result": null,
                    "error": error.clone(),
                    "id": "zecd"
                })),
                (None, Ok(txid)) => reply(json!(txid)),
                (None, Err((code, msg))) => err(*code, msg),
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
            CleartextPolicy::default(),
        )
        .await
        .expect("connect to fake zebrad")
    }

    #[tokio::test]
    async fn transparent_txids_maps_getaddresstxids() {
        let mut fake = Fake::new();
        let addr = "t1KnownTransparentAddressForTest".to_string();
        // A display-hex txid (64 chars). `parse_display_txid` reverses to internal order, and
        // `TxId::to_string` reverses back, so the round-trip equals the input.
        let txid_hex = format!("aa{}", "bb".repeat(31));
        fake.addr_txids.insert(addr.clone(), vec![txid_hex.clone()]);
        let mut src = source_for(Arc::new(Mutex::new(fake))).await;

        let got = src.transparent_txids(vec![addr], 1, 100).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to_string(), txid_hex);

        // An address with no recorded txids yields an empty list, not an error.
        let none = src
            .transparent_txids(vec!["t1Unseen".into()], 1, 100)
            .await
            .unwrap();
        assert!(none.is_empty());

        // A batch query returns the union across addresses (zebra accepts many per call).
        let mut fake2 = Fake::new();
        let (a, b) = ("t1Aaa".to_string(), "t1Bbb".to_string());
        fake2
            .addr_txids
            .insert(a.clone(), vec![format!("11{}", "22".repeat(31))]);
        fake2
            .addr_txids
            .insert(b.clone(), vec![format!("33{}", "44".repeat(31))]);
        let mut src2 = source_for(Arc::new(Mutex::new(fake2))).await;
        let both = src2.transparent_txids(vec![a, b], 1, 100).await.unwrap();
        assert_eq!(both.len(), 2, "batch query unions txids across addresses");
    }

    #[tokio::test]
    async fn get_address_utxos_maps_getaddressutxos() {
        let mut fake = Fake::new();
        let addr = "t1KnownTransparentAddressForTest".to_string();
        let txid_hex = format!("aa{}", "bb".repeat(31));
        fake.addr_utxos.insert(
            addr.clone(),
            vec![json!({
                "address": addr,
                "txid": txid_hex,
                "outputIndex": 2,
                // p2pkh script (25 bytes): OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                "script": format!("76a914{}88ac", "00".repeat(20)),
                "satoshis": 100_000_000u64,
                "height": 42,
            })],
        );
        let mut src = source_for(Arc::new(Mutex::new(fake))).await;

        let utxos = src.get_address_utxos(vec![addr]).await.unwrap();
        assert_eq!(utxos.len(), 1);
        let u = &utxos[0];
        assert_eq!(
            u.txid.to_string(),
            txid_hex,
            "txid round-trips display order"
        );
        assert_eq!(u.index, 2);
        assert_eq!(u.value_zat, 100_000_000);
        assert_eq!(u.height, Some(42));
        assert_eq!(u.script.len(), 25, "p2pkh script_pubkey decoded from hex");

        // An address with no UTXOs yields an empty list, not an error.
        let none = src
            .get_address_utxos(vec!["t1Unseen".into()])
            .await
            .unwrap();
        assert!(none.is_empty());
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

    /// Regression guard for the tip-advance step of the -25 (already-expired) send fix: a
    /// spend's expiry height is derived from the wallet DB's chain tip, so before building one
    /// the actor pulls the upstream's *real* tip into the DB and scans up to it (`do_send` →
    /// `sync_to_tip_for_send` → `fetch_and_store_chain_tip`, then a catch-up scan). This covers
    /// the tip-advance half: the DB starts at a stale height far below the upstream's, and one
    /// call must advance it to the upstream tip (the actor then scans the gap so the anchor is
    /// valid too). If the tip didn't advance, a send would expire against the stale height.
    #[tokio::test]
    async fn fetch_and_store_chain_tip_advances_a_stale_wallet_db_height() {
        use zcash_client_backend::data_api::chain::ChainState;
        use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};
        use zcash_primitives::block::BlockHash;

        // Upstream reports height 415000 (the fixture tip).
        let fake = Arc::new(Mutex::new(Fake::new()));
        let mut src = source_for(fake).await;

        // A wallet DB whose recorded tip lags the chain by a wide margin - the sync-starvation
        // condition that produced already-expired sends. (`chain_height` reads the scan-queue
        // extent, which `update_chain_tip` only populates for heights at/after the account's
        // birthday and the network's shielded activation - use regtest, which activates at
        // height 1, so both the stale and the real tip register.)
        let net = crate::network::regtest();
        let dir = tempfile::tempdir().unwrap();
        let mut db = crate::wallet::open::init_dbs(net, dir.path()).expect("init dbs");
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
            None,
        );
        db.create_account(
            "t",
            &secrecy::SecretVec::new(vec![1u8; 64]),
            &birthday,
            None,
        )
        .expect("create account");
        db.update_chain_tip(BlockHeight::from_u32(100))
            .expect("seed a stale tip");
        assert_eq!(db.chain_height().unwrap(), Some(BlockHeight::from_u32(100)));

        // One refresh pulls the real tip into the DB, so the next spend expires against it.
        let (tip, hash) = crate::wallet::actor::fetch_and_store_chain_tip(&mut src, &mut db)
            .await
            .expect("refresh tip");
        assert_eq!(tip, BlockHeight::from_u32(415000));
        assert_eq!(hash, internal(BLOCK_415000_HASH));
        assert_eq!(
            db.chain_height().unwrap(),
            Some(BlockHeight::from_u32(415000)),
            "the wallet DB tip must advance to the upstream tip"
        );
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
        let mut src = ZebraSource::connect(
            &addr.ip().to_string(),
            addr.port(),
            &auth,
            ZNetwork::Main,
            CleartextPolicy::default(),
        )
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
        let mut src = ZebraSource::connect(
            &addr2.ip().to_string(),
            addr2.port(),
            &auth,
            ZNetwork::Main,
            CleartextPolicy::default(),
        )
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

    /// A node serving a tree state for the wrong height must fail the request, not feed the
    /// scanner a corrupted birthday anchor (which it enforces with a panic). Mirrors the
    /// raw-block `claimed_height` guard.
    #[tokio::test]
    async fn tree_state_rejects_height_mismatch() {
        let fake = Arc::new(Mutex::new(Fake::new()));
        fake.lock().unwrap().treestate = json!({
            "hash": BLOCK_415000_HASH,
            "height": 415000,
            "time": 1540144808,
            "sapling": { "commitments": {} },
            "orchard": {},
        });
        let mut src = source_for(fake).await;
        // Request one block earlier than the node returns.
        let err = src
            .tree_state(BlockHeight::from_u32(414999))
            .await
            .expect_err("height mismatch must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("414999") && msg.contains("415000"),
            "got: {msg}"
        );
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
    async fn broadcast_codeless_error_envelope_is_a_rejection_not_acceptance() {
        // A valid-JSON error envelope carrying a message but no numeric `code` - the shape a
        // proxy/load balancer fronting zebra can emit. It must parse as a rejection, never as
        // an accepted broadcast: a `code` defaulting to 0 would collide with the acceptance
        // sentinel and tell the caller a never-relayed tx succeeded.
        let fake = Arc::new(Mutex::new(Fake::new()));
        let mut src = source_for(fake.clone()).await;

        // Missing `code` entirely.
        fake.lock().unwrap().send_error_object = Some(json!({ "message": "rejected by proxy" }));
        let outcome = src.broadcast_tx(vec![0xab; 8]).await.unwrap();
        assert!(
            !outcome.is_accepted(),
            "a code-less error must not look like acceptance"
        );
        assert_ne!(outcome.error_code, 0);
        assert_eq!(outcome.error_message, "rejected by proxy");

        // Explicit `code: 0` (also collides with the success sentinel) and a non-integer code.
        for body in [
            json!({ "code": 0, "message": "zero code" }),
            json!({ "code": "oops", "message": "string code" }),
        ] {
            fake.lock().unwrap().send_error_object = Some(body);
            let outcome = src.broadcast_tx(vec![0xab; 8]).await.unwrap();
            assert!(!outcome.is_accepted());
            assert_ne!(outcome.error_code, 0);
        }
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
            .compact_block_range(
                BlockHeight::from_u32(415000),
                BlockHeight::from_u32(415000),
                true,
            )
            .await
            .unwrap();

        let (cb, transparent) = stream.next().await.unwrap().expect("one block");
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

        // `include_transparent` harvested the block's transparent outputs from the same parsed
        // block. This block's lone (coinbase) tx has transparent outputs (the miner reward +
        // founders'/funding-stream outputs), all tagged with the block height and the coinbase
        // txid - the receive-discovery source for the wallet's transparent addresses.
        assert!(
            !transparent.is_empty(),
            "the coinbase tx's transparent outputs were extracted"
        );
        for u in &transparent {
            assert_eq!(u.height, Some(415000));
            assert_eq!(
                &u.txid.as_ref()[..],
                &internal(BLOCK_415000_COINBASE_TXID)[..]
            );
        }

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
            .compact_block_range(BlockHeight::from_u32(5), BlockHeight::from_u32(5), false)
            .await
            .unwrap();
        let err = stream.next().await.expect_err("height mismatch must error");
        assert!(
            err.to_string().contains("claiming height 415000"),
            "got: {err:#}"
        );

        let mut stream = src
            .compact_block_range(BlockHeight::from_u32(6), BlockHeight::from_u32(6), false)
            .await
            .unwrap();
        assert!(
            stream.next().await.is_err(),
            "unparseable block bytes must error"
        );
    }

    /// A block with more than `u16::MAX` transactions would overflow the scanner's 16-bit
    /// per-block transaction index and panic librustzcash. Such a block is non-consensus (only
    /// a malicious or buggy upstream produces it), so the stream must reject it as a transport
    /// error before it reaches `block_to_compact`.
    #[tokio::test]
    async fn block_range_rejects_more_than_u16_max_transactions() {
        fn compact_size(n: u64, out: &mut Vec<u8>) {
            if n < 0xFD {
                out.push(n as u8);
            } else if n <= 0xFFFF {
                out.push(0xFD);
                out.extend_from_slice(&(n as u16).to_le_bytes());
            } else if n <= 0xFFFF_FFFF {
                out.push(0xFE);
                out.extend_from_slice(&(n as u32).to_le_bytes());
            } else {
                out.push(0xFF);
                out.extend_from_slice(&n.to_le_bytes());
            }
        }

        // One over the 16-bit limit: a valid coinbase plus this many minimal transactions. The
        // bytes only need to *parse* - we want the vtx-count guard, not a parse error, to reject.
        const TX_COUNT: u64 = u16::MAX as u64 + 1; // 65_536

        let mut raw = Vec::new();
        // Block header: version, prev, merkle, final_sapling_root, time, bits, nonce, empty solution.
        raw.extend_from_slice(&4i32.to_le_bytes());
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&[0u8; 32]);
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&[0u8; 32]);
        raw.push(0x00); // solution: empty vector

        compact_size(TX_COUNT, &mut raw);

        // Coinbase (v1) claiming height 1: a single NULL-prevout input whose scriptSig pushes
        // the 1-byte height, and no outputs.
        raw.extend_from_slice(&1u32.to_le_bytes()); // version
        raw.push(0x01); // one input
        raw.extend_from_slice(&[0u8; 32]); // prevout hash (NULL)
        raw.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // prevout index (NULL)
        raw.extend_from_slice(&[0x02, 0x01, 0x01]); // scriptSig: push the 1-byte height 0x01
        raw.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sequence
        raw.push(0x00); // no outputs
        raw.extend_from_slice(&0u32.to_le_bytes()); // lock_time

        // The remaining minimal empty v1 transactions.
        let mut mintx = Vec::new();
        mintx.extend_from_slice(&1u32.to_le_bytes()); // version
        mintx.push(0x00); // no inputs
        mintx.push(0x00); // no outputs
        mintx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        for _ in 0..(TX_COUNT - 1) {
            raw.extend_from_slice(&mintx);
        }

        let fake = Arc::new(Mutex::new(Fake::new()));
        fake.lock()
            .unwrap()
            .raw_blocks
            .insert("1".into(), hex::encode(&raw));
        let mut src = source_for(fake).await;

        let mut stream = src
            .compact_block_range(BlockHeight::from_u32(1), BlockHeight::from_u32(1), false)
            .await
            .unwrap();
        let err = stream
            .next()
            .await
            .expect_err("an over-large block must error, not panic");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("65536") && msg.contains("transactions"),
            "got: {msg}"
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
        let MempoolStream::Zebra(mut stream) = src.subscribe_mempool().await.unwrap();

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
