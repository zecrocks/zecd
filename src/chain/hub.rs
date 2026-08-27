//! [`ChainHub`]: one upstream connection, shared by every wallet actor in the daemon.
//!
//! # Why
//!
//! zecd's sharing unit used to be the wallet: each [`crate::wallet::actor::WalletActor`] dialed
//! its own [`AnySource`], polled its own chain tip, ran its own mempool poller, and streamed its
//! own copy of the subtree roots at connect. That is fine for the one-or-two-wallet deployments
//! zecd was built for and untenable for a daemon monitoring a fleet: at N wallets a single zebrad
//! sees N connections, N `getblockchaininfo` polls per sync interval, and - the worst of them -
//! N/2 `getrawmempool` calls **per second**, since the zebra mempool poller ticks every 2s per
//! wallet. None of that work is wallet-specific: the chain is the same chain for everybody.
//!
//! The hub owns the connection and hands each consumer a [`HubSource`], itself a [`ChainSource`],
//! so nothing above `chain/` knows the difference. What it collapses from N to 1:
//!
//! * **the connection** - one dial, one TLS handshake, one file descriptor. Both backends are
//!   cheap to clone onto (hyper pools connections, tonic multiplexes one HTTP/2 channel), so
//!   consumers get their own handle and calls stay concurrent; only the dial itself is serialized.
//! * **the mempool subscription** - one poller/stream, fanned out over a `broadcast` channel with
//!   a replay buffer so a consumer that subscribes mid-block still sees the current mempool.
//! * **the subtree roots** - hundreds of roots streamed once per connection instead of once per
//!   wallet, which is the single largest fixed cost in the connect path.
//! * **the chain tip** - a short TTL, so N actors ticking on the same interval cost one
//!   `getblockchaininfo`.
//! * **`server_info`** - constant for a connection's life (it is the wrong-chain guard's input).
//! * **transaction fetches** - an LRU, so a transaction paying many monitored wallets is fetched
//!   once during enhancement rather than once per wallet.
//!
//! # What it deliberately does *not* cache
//!
//! Compact block ranges pass straight through. Caching them by height is not safe without also
//! tracking which fork each cached block belongs to: a range served wholly from a stale cache
//! after a reorg would make the wallet scan an abandoned fork, hit librustzcash's continuity
//! check at the join point, rewind, and be served the same stale blocks again. The wins that
//! would come from block sharing are instead taken structurally, by putting many accounts behind
//! one scan: a fleet's block fetches then scale with the number of scan domains, not the number
//! of wallets.
//!
//! # Failure handling
//!
//! Every consumer call that fails invalidates the shared connection *for its own generation*
//! only. The next [`ChainHub::acquire`] re-dials under the connection mutex, so N actors reacting
//! to one outage produce one dial and then share its result - no thundering herd, and the actors'
//! existing per-wallet backoff still paces how often they ask.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex};
use zcash_client_backend::proto::service;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::{ShieldedPool, TxId};

use crate::backend::Server;
use crate::chain::{
    AbortOnDrop, AnySource, BroadcastOutcome, ChainSource, ChainTip, CompactBlockStream, FetchedTx,
    MempoolStream, ServerInfo, SubtreeRootInfo, TxEvidence,
};

/// How long a fetched chain tip is served to other consumers before it is re-fetched. Sized well
/// under a block interval on every network: it exists so that N actors ticking together cost one
/// upstream call, not to slow the daemon's reaction to a new block (the mempool stream's
/// close-on-new-block signal is what actually drives that).
const TIP_TTL: Duration = Duration::from_millis(750);

/// Transactions kept in the fetch cache. Enhancement is the heavy user: on a deep restore it
/// fetches one full transaction per wallet transaction, and in a fleet the same transaction is
/// often relevant to many wallets at once. Bounded so a restore cannot grow it without limit.
const TX_CACHE_ENTRIES: usize = 2048;

/// Mempool transactions retained for replay to a consumer that subscribes mid-block. The upstream
/// sends the current mempool when a subscription opens, so without this a wallet that finishes
/// catching up between blocks would see an empty mempool and miss every 0-conf credit until the
/// next block. Overflow is harmless: an unreplayed transaction is simply credited when it mines.
const MEMPOOL_REPLAY_TXS: usize = 4096;

/// Broadcast channel depth for the mempool fan-out. A consumer that falls this far behind loses
/// the intervening transactions (`RecvError::Lagged`), which costs 0-conf visibility for those
/// transactions only - the block scan still credits them when they mine.
const MEMPOOL_CHANNEL_CAP: usize = 4096;

/// One shared upstream connection plus the caches and fan-outs that make it serve many wallets.
///
/// Constructed once per daemon (`node.rs`) and shared as an `Arc`; consumers call
/// [`ChainHub::acquire`] to get a [`HubSource`] and use it exactly as they used an [`AnySource`].
pub struct ChainHub {
    server: Server,
    connect_timeout: Duration,
    /// The live connection, its generation, and the caches keyed to it. Held only across a dial
    /// (and the brief clone-out on acquire), never across an ordinary RPC.
    conn: Mutex<Conn>,
    /// Chain tip, with [`TIP_TTL`] freshness. A separate lock from `conn` so a tip refresh cannot
    /// be stuck behind a dial, and held across the fetch so concurrent refreshes coalesce into
    /// one upstream call rather than racing.
    tip: Mutex<TipCache>,
    /// `server_info` and the per-pool subtree roots, both constant for a connection's lifetime.
    info: Mutex<InfoCache>,
    /// Fetched transactions, keyed by txid. Cleared whenever the observed tip stops extending
    /// (a reorg can change a transaction's mined height, which callers store).
    txs: std::sync::Mutex<LruMap<TxId, FetchedTx>>,
    /// The single mempool subscription and its fan-out.
    mempool: Mutex<MempoolHub>,
    stats: HubStats,
}

/// The shared connection and the generation it belongs to.
///
/// The generation is what makes error handling safe under concurrency: a consumer reports a
/// failure against the generation it was using, so a late error from an already-replaced
/// connection cannot tear down the healthy one that replaced it.
struct Conn {
    source: Option<AnySource>,
    generation: u64,
}

#[derive(Default)]
struct TipCache {
    /// The last tip observed, and when. `None` until the first successful fetch.
    tip: Option<(ChainTip, Instant)>,
    /// The generation `tip` was fetched on; a tip from a previous connection is not reused.
    generation: u64,
}

#[derive(Default)]
struct InfoCache {
    generation: u64,
    server_info: Option<ServerInfo>,
    roots: HashMap<u8, Vec<SubtreeRootInfo>>,
}

/// Counters for what the hub actually sent upstream, so tests can assert the collapsing
/// (N consumers, one call) rather than inferring it from timing, and operators can see it.
#[derive(Default)]
pub struct HubStats {
    /// Successful dials (each one starts a new generation).
    pub connects: AtomicU64,
    /// `latest_block` calls that missed the TTL and went upstream.
    pub tip_fetches: AtomicU64,
    /// `server_info` calls that went upstream.
    pub server_info_fetches: AtomicU64,
    /// `subtree_roots` calls that went upstream.
    pub subtree_root_fetches: AtomicU64,
    /// `fetch_tx` calls that missed the cache and went upstream.
    pub tx_fetches: AtomicU64,
    /// `fetch_tx` calls served from the cache.
    pub tx_cache_hits: AtomicU64,
    /// Mempool subscriptions opened upstream (one per block, not one per wallet).
    pub mempool_subscriptions: AtomicU64,
}

impl ChainHub {
    /// Build a hub over `server`. No connection is made until the first [`ChainHub::acquire`].
    pub fn new(server: Server, connect_timeout: Duration) -> Arc<Self> {
        Arc::new(ChainHub {
            server,
            connect_timeout,
            conn: Mutex::new(Conn {
                source: None,
                generation: 0,
            }),
            tip: Mutex::new(TipCache::default()),
            info: Mutex::new(InfoCache::default()),
            txs: std::sync::Mutex::new(LruMap::new(TX_CACHE_ENTRIES)),
            mempool: Mutex::new(MempoolHub::default()),
            stats: HubStats::default(),
        })
    }

    /// The endpoint this hub connects to (for logs and `getpeerinfo`).
    pub fn server(&self) -> &Server {
        &self.server
    }

    pub fn stats(&self) -> &HubStats {
        &self.stats
    }

    /// Get a handle onto the shared connection, dialing it if it is down.
    ///
    /// Serialized by the connection mutex, which is the whole point: when N wallets react to one
    /// outage, the first through dials and the rest clone its result. Errors propagate to the
    /// caller unchanged, so each wallet's own backoff still paces its retries.
    pub async fn acquire(self: &Arc<Self>) -> anyhow::Result<HubSource> {
        let mut conn = self.conn.lock().await;
        if conn.source.is_none() {
            let source = self.server.connect_timeout(self.connect_timeout).await?;
            conn.generation += 1;
            conn.source = Some(source);
            self.stats.connects.fetch_add(1, Ordering::Relaxed);
        }
        let generation = conn.generation;
        let source = conn.source.as_ref().expect("connected above").clone();
        drop(conn);
        Ok(HubSource {
            hub: Arc::clone(self),
            generation,
            inner: source,
        })
    }

    /// Drop the shared connection if it is still the one `generation` names, so the next
    /// [`ChainHub::acquire`] re-dials. A report against a superseded generation is ignored.
    async fn invalidate(&self, generation: u64) {
        let mut conn = self.conn.lock().await;
        if conn.generation != generation || conn.source.is_none() {
            return;
        }
        conn.source = None;
        drop(conn);
        // The mempool pump holds its own clone of the dead connection; stop it so the next
        // subscription opens against the replacement rather than waiting for the old stream to
        // notice. Caches keyed to the connection are dropped with it.
        let mut mempool = self.mempool.lock().await;
        if mempool.generation == generation {
            mempool.shutdown();
        }
        self.txs.lock().expect("tx cache mutex").clear();
    }

    /// Note an observed tip, dropping tip-dependent caches whenever the tip *changed*. A
    /// transaction's mined height can change across a reorg, and callers store that height, so a
    /// cached transaction from an abandoned fork must not be reused - and a tip poll cannot tell
    /// an ordinary new block from a reorg observed at a greater height ([`ChainTip`] carries no
    /// parent hash, and the replacement chain is usually longer by the time the next poll sees
    /// it). So the cache lives exactly one block window: any new hash clears it. That still
    /// serves the burst the cache exists for - N shard wallets enhancing the same transaction
    /// right after it lands - while never surviving into a chain where its heights may be wrong.
    fn note_tip(&self, previous: Option<&ChainTip>, current: &ChainTip) {
        let same_tip = match previous {
            None => true,
            Some(prev) => current.height == prev.height && current.hash == prev.hash,
        };
        if !same_tip {
            self.txs.lock().expect("tx cache mutex").clear();
        }
    }
}

/// A consumer's handle onto the hub's shared connection: a full [`ChainSource`], so the sync
/// engine, the actor, and everything else above `chain/` are unchanged.
///
/// Holds its own clone of the backend client, so ordinary RPCs run concurrently across consumers;
/// only the cached calls take a lock, and they take it to coalesce (one upstream call for N
/// simultaneous askers) rather than to protect the connection.
pub struct HubSource {
    hub: Arc<ChainHub>,
    /// The connection generation this handle was issued for; failures are reported against it.
    generation: u64,
    inner: AnySource,
}

impl HubSource {
    /// The connection generation behind this handle (tests and diagnostics).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Report a transport failure against this handle's generation, so the shared connection is
    /// re-dialed once rather than once per consumer.
    async fn failed(&self) {
        self.hub.invalidate(self.generation).await;
    }

    /// Pass a completed call's result through, invalidating the shared connection on a
    /// transport-class error. Takes the result rather than the future so the `&mut self.inner`
    /// borrow the call needs has already ended by the time the hub is consulted.
    async fn checked<T>(&self, result: anyhow::Result<T>) -> anyhow::Result<T> {
        if result.is_err() {
            self.failed().await;
        }
        result
    }
}

impl ChainSource for HubSource {
    /// TTL-cached: N actors polling on the same interval cost one upstream call. The lock is held
    /// across the fetch so simultaneous misses coalesce instead of racing.
    async fn latest_block(&mut self) -> anyhow::Result<ChainTip> {
        let mut cache = self.hub.tip.lock().await;
        if cache.generation == self.generation {
            if let Some((tip, at)) = &cache.tip {
                if at.elapsed() < TIP_TTL {
                    return Ok(tip.clone());
                }
            }
        }
        let previous = cache.tip.as_ref().map(|(tip, _)| tip.clone());
        self.hub.stats.tip_fetches.fetch_add(1, Ordering::Relaxed);
        let tip = match self.inner.latest_block().await {
            Ok(tip) => tip,
            Err(e) => {
                drop(cache);
                self.failed().await;
                return Err(e);
            }
        };
        self.hub.note_tip(previous.as_ref(), &tip);
        cache.generation = self.generation;
        cache.tip = Some((tip.clone(), Instant::now()));
        Ok(tip)
    }

    /// Passthrough. Tree states are requested at a wallet's birthday and at each scan batch's
    /// start, which do not repeat across wallets often enough to be worth a cache that would have
    /// to be reorg-aware.
    async fn tree_state(&mut self, height: BlockHeight) -> anyhow::Result<service::TreeState> {
        let result = self.inner.tree_state(height).await;
        self.checked(result).await
    }

    /// Passthrough - see the module docs on why block ranges are deliberately not cached.
    async fn compact_block_range(
        &mut self,
        start: BlockHeight,
        end: BlockHeight,
        include_transparent: bool,
    ) -> anyhow::Result<CompactBlockStream> {
        let result = self
            .inner
            .compact_block_range(start, end, include_transparent)
            .await;
        self.checked(result).await
    }

    /// Cached for the connection's lifetime. This is the largest fixed cost in the connect path -
    /// every Sapling and Orchard subtree root since activation, streamed in full - and it is
    /// identical for every wallet on the chain.
    async fn subtree_roots(
        &mut self,
        protocol: ShieldedPool,
    ) -> anyhow::Result<Vec<SubtreeRootInfo>> {
        let key = pool_key(protocol);
        let mut cache = self.hub.info.lock().await;
        if cache.generation == self.generation {
            if let Some(roots) = cache.roots.get(&key) {
                return Ok(roots.clone());
            }
        } else {
            *cache = InfoCache {
                generation: self.generation,
                ..InfoCache::default()
            };
        }
        self.hub
            .stats
            .subtree_root_fetches
            .fetch_add(1, Ordering::Relaxed);
        let roots = match self.inner.subtree_roots(protocol).await {
            Ok(roots) => roots,
            Err(e) => {
                drop(cache);
                self.failed().await;
                return Err(e);
            }
        };
        cache.roots.insert(key, roots.clone());
        Ok(roots)
    }

    /// Cached for the connection's lifetime: the upstream's identity and upgrade set cannot
    /// change without a reconnect, and every wallet's connect path asks for it.
    async fn server_info(&mut self) -> anyhow::Result<ServerInfo> {
        let mut cache = self.hub.info.lock().await;
        if cache.generation == self.generation {
            if let Some(info) = &cache.server_info {
                return Ok(info.clone());
            }
        } else {
            *cache = InfoCache {
                generation: self.generation,
                ..InfoCache::default()
            };
        }
        self.hub
            .stats
            .server_info_fetches
            .fetch_add(1, Ordering::Relaxed);
        let info = match self.inner.server_info().await {
            Ok(info) => info,
            Err(e) => {
                drop(cache);
                self.failed().await;
                return Err(e);
            }
        };
        cache.server_info = Some(info.clone());
        Ok(info)
    }

    /// Passthrough, never cached: a broadcast is an action, not a query.
    async fn broadcast_tx(&mut self, data: Vec<u8>) -> anyhow::Result<BroadcastOutcome> {
        let result = self.inner.broadcast_tx(data).await;
        self.checked(result).await
    }

    /// LRU-cached. A transaction paying many monitored wallets is enhanced by each of them; the
    /// bytes are identical, so the fetch happens once. The cache is dropped whenever the observed
    /// tip stops extending, because a reorg can move a transaction's mined height (which callers
    /// store alongside the bytes).
    ///
    /// A negative result (`Ok(None)`, upstream does not know the txid) is not cached: an unmined
    /// transaction the upstream has not seen yet is exactly the case a retry is meant to resolve.
    async fn fetch_tx(&mut self, txid: TxId) -> anyhow::Result<Option<FetchedTx>> {
        if let Some(hit) = self
            .hub
            .txs
            .lock()
            .expect("tx cache mutex")
            .get(&txid)
            .cloned()
        {
            self.hub.stats.tx_cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(hit));
        }
        self.hub.stats.tx_fetches.fetch_add(1, Ordering::Relaxed);
        let result = self.inner.fetch_tx(txid).await;
        let fetched = self.checked(result).await?;
        if let Some(tx) = &fetched {
            self.hub
                .txs
                .lock()
                .expect("tx cache mutex")
                .insert(txid, tx.clone());
        }
        Ok(fetched)
    }

    /// Passthrough: the answer is per-address and per-range, and the ranges callers ask for walk
    /// forward with the chain tip.
    async fn transparent_tx_evidence(
        &mut self,
        addresses: Vec<String>,
        start: u32,
        end: u32,
    ) -> anyhow::Result<Vec<TxEvidence>> {
        let result = self
            .inner
            .transparent_tx_evidence(addresses, start, end)
            .await;
        self.checked(result).await
    }

    fn block_scan_covers_transparent(&self) -> bool {
        self.inner.block_scan_covers_transparent()
    }

    /// Join the shared subscription rather than opening one. The first caller after each block
    /// starts the single upstream stream; the rest attach to its fan-out and are replayed the
    /// transactions it has already seen this block, so a wallet that subscribes mid-block still
    /// gets the full mempool view the upstream sent when the stream opened.
    async fn subscribe_mempool(&mut self) -> anyhow::Result<MempoolStream> {
        let mut hub = self.hub.mempool.lock().await;
        // Only a *newer* generation supersedes the pump: its stream was opened on a connection
        // that has since been invalidated. A handle still on an older generation (its clone of
        // the connection kept working, so it never reacquired) joins the live pump instead -
        // treating any mismatch symmetrically would let one stale handle tear down the fresh
        // subscription on every block, ping-ponging with the reacquired handles forever.
        if self.generation > hub.generation {
            hub.shutdown();
            hub.generation = self.generation;
        }
        if let Some(sub) = hub.subscribe() {
            return Ok(MempoolStream::Hub(sub));
        }
        self.hub
            .stats
            .mempool_subscriptions
            .fetch_add(1, Ordering::Relaxed);
        let stream = match self.inner.subscribe_mempool().await {
            Ok(stream) => stream,
            Err(e) => {
                drop(hub);
                self.failed().await;
                return Err(e);
            }
        };
        let sub = hub.start(stream);
        Ok(MempoolStream::Hub(sub))
    }
}

/// The roots cache's per-pool key. The match is deliberately exhaustive (no `_` arm): a pool
/// upstream adds later fails to compile here, forcing it to get its own key rather than silently
/// colliding with another pool and serving its cached roots.
fn pool_key(protocol: ShieldedPool) -> u8 {
    match protocol {
        ShieldedPool::Sapling => 0,
        ShieldedPool::Orchard => 1,
        ShieldedPool::Ironwood => 2,
    }
}

// ---------------------------------------------------------------------------
// Mempool fan-out
// ---------------------------------------------------------------------------

/// One item on the shared mempool channel. `Closed` carries the upstream's close-on-new-block
/// signal - the actors' "sync now" trigger - to every subscriber.
#[derive(Clone)]
enum MempoolItem {
    Tx(Arc<service::RawTransaction>),
    Closed,
}

/// The single upstream mempool subscription and everything needed to fan it out: the broadcast
/// sender, the replay buffer for late subscribers, and the pump task reading the upstream stream.
#[derive(Default)]
struct MempoolHub {
    generation: u64,
    tx: Option<broadcast::Sender<MempoolItem>>,
    /// Transactions seen on the current subscription, replayed to late subscribers.
    replay: Arc<std::sync::Mutex<Vec<Arc<service::RawTransaction>>>>,
    /// Set once the upstream stream closes (a new block); the next subscriber starts a new one.
    closed: Arc<std::sync::atomic::AtomicBool>,
    pump: Option<AbortOnDrop>,
}

impl MempoolHub {
    /// Attach to the live subscription, if there is one that has not yet closed.
    fn subscribe(&self) -> Option<HubMempoolStream> {
        let tx = self.tx.as_ref()?;
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        // Subscribe to the live channel *before* snapshotting the replay buffer. The pump pushes
        // to the buffer and then broadcasts without taking the hub lock, so a transaction landing
        // between the two steps is seen twice in this order (replay + live; harmless, the actor's
        // decrypt-and-store is idempotent) - in the other order it would be seen by neither.
        let rx = tx.subscribe();
        let replay = self
            .replay
            .lock()
            .expect("mempool replay mutex")
            .iter()
            .cloned()
            .collect::<VecDeque<_>>();
        Some(HubMempoolStream {
            rx,
            replay,
            done: false,
        })
    }

    /// Start pumping `stream` into a fresh fan-out and return the first subscriber.
    fn start(&mut self, mut stream: MempoolStream) -> HubMempoolStream {
        let (tx, rx) = broadcast::channel(MEMPOOL_CHANNEL_CAP);
        let replay = Arc::new(std::sync::Mutex::new(Vec::new()));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pump_tx = tx.clone();
        let pump_replay = Arc::clone(&replay);
        let pump_closed = Arc::clone(&closed);
        // The pump runs detached so consumers never block on upstream I/O. It ends when the
        // upstream closes the stream (a new block), errors, or the hub aborts it on invalidate -
        // in every case after telling subscribers, so an actor waiting on the stream is woken.
        let task = tokio::spawn(async move {
            loop {
                match stream.message().await {
                    Ok(Some(raw)) => {
                        let raw = Arc::new(raw);
                        {
                            let mut buf = pump_replay.lock().expect("mempool replay mutex");
                            if buf.len() < MEMPOOL_REPLAY_TXS {
                                buf.push(Arc::clone(&raw));
                            }
                        }
                        // An error here only means nobody is listening yet; the replay buffer
                        // still carries the transaction to the next subscriber.
                        let _ = pump_tx.send(MempoolItem::Tx(raw));
                    }
                    Ok(None) => {
                        pump_closed.store(true, Ordering::Release);
                        let _ = pump_tx.send(MempoolItem::Closed);
                        return;
                    }
                    Err(e) => {
                        tracing::debug!("shared mempool stream error: {e}");
                        pump_closed.store(true, Ordering::Release);
                        let _ = pump_tx.send(MempoolItem::Closed);
                        return;
                    }
                }
            }
        });
        self.tx = Some(tx);
        self.replay = replay;
        self.closed = closed;
        self.pump = Some(AbortOnDrop(task));
        HubMempoolStream {
            rx,
            replay: VecDeque::new(),
            done: false,
        }
    }

    /// Tear the subscription down: subscribers see end-of-stream and the next one starts afresh.
    fn shutdown(&mut self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(MempoolItem::Closed);
        }
        self.closed.store(true, Ordering::Release);
        self.pump = None;
        self.tx = None;
    }
}

/// One consumer's view of the shared mempool subscription.
///
/// Yields the transactions buffered before it attached, then the live ones, then `Ok(None)` when
/// the upstream closes on a new block - the same contract [`MempoolStream`] has always had, which
/// is what the actor uses as its sync-now signal.
pub struct HubMempoolStream {
    rx: broadcast::Receiver<MempoolItem>,
    /// Transactions the shared stream saw before this consumer attached, drained first.
    replay: VecDeque<Arc<service::RawTransaction>>,
    done: bool,
}

impl HubMempoolStream {
    pub async fn message(&mut self) -> anyhow::Result<Option<service::RawTransaction>> {
        if let Some(raw) = self.replay.pop_front() {
            return Ok(Some((*raw).clone()));
        }
        if self.done {
            return Ok(None);
        }
        loop {
            match self.rx.recv().await {
                Ok(MempoolItem::Tx(raw)) => return Ok(Some((*raw).clone())),
                Ok(MempoolItem::Closed) => {
                    self.done = true;
                    return Ok(None);
                }
                // This consumer fell behind the fan-out and lost the intervening transactions.
                // 0-conf visibility for those is lost; the block scan still credits them when
                // they mine, which is the same guarantee a dropped subscription has always had.
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::debug!("mempool fan-out lagged, dropped {n} transaction(s)");
                }
                Err(broadcast::error::RecvError::Closed) => {
                    self.done = true;
                    return Ok(None);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// A small LRU
// ---------------------------------------------------------------------------

/// A bounded least-recently-used map, sized for the hub's transaction cache.
///
/// Hand-rolled rather than pulled in as a dependency: the hub needs one map with three
/// operations, and this repo keeps its dependency surface deliberately small.
struct LruMap<K, V> {
    cap: usize,
    map: HashMap<K, V>,
    /// Keys in least-to-most recently used order. `get` moves a key to the back.
    order: VecDeque<K>,
}

impl<K: std::hash::Hash + Eq + Clone, V> LruMap<K, V> {
    fn new(cap: usize) -> Self {
        LruMap {
            cap,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        if !self.map.contains_key(key) {
            return None;
        }
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            let k = self.order.remove(pos).expect("position just found");
            self.order.push_back(k);
        }
        self.map.get(key)
    }

    fn insert(&mut self, key: K, value: V) {
        if self.map.insert(key.clone(), value).is_some() {
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
        }
        self.order.push_back(key);
        while self.order.len() > self.cap {
            if let Some(evict) = self.order.pop_front() {
                self.map.remove(&evict);
            }
        }
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolved endpoint for the cache/generation tests. Nothing here dials it - the tests
    /// exercise the hub's bookkeeping, and the live paths are covered by the regtest tier.
    fn test_server() -> Server {
        crate::backend::resolve("zebra://127.0.0.1:18234", crate::network::ZNetwork::Test)
            .expect("a loopback zebra endpoint resolves")
    }

    #[test]
    fn lru_evicts_the_least_recently_used_entry() {
        let mut lru: LruMap<u32, u32> = LruMap::new(2);
        lru.insert(1, 10);
        lru.insert(2, 20);
        // Touching 1 makes 2 the eviction candidate, not 1 (insertion order alone would evict 1).
        assert_eq!(lru.get(&1), Some(&10));
        lru.insert(3, 30);
        assert_eq!(lru.len(), 2);
        assert_eq!(lru.get(&1), Some(&10));
        assert_eq!(lru.get(&2), None, "least recently used entry was evicted");
        assert_eq!(lru.get(&3), Some(&30));
    }

    #[test]
    fn lru_reinsert_updates_the_value_without_growing() {
        let mut lru: LruMap<u32, u32> = LruMap::new(2);
        lru.insert(1, 10);
        lru.insert(1, 11);
        assert_eq!(lru.len(), 1, "re-insert must not duplicate the key");
        assert_eq!(lru.get(&1), Some(&11));
        // The recency entry was rewritten too, so a third key evicts the *other* one.
        lru.insert(2, 20);
        lru.insert(3, 30);
        assert_eq!(lru.get(&1), None);
    }

    #[test]
    fn lru_clear_empties_both_halves() {
        let mut lru: LruMap<u32, u32> = LruMap::new(4);
        lru.insert(1, 10);
        lru.insert(2, 20);
        lru.clear();
        assert_eq!(lru.len(), 0);
        assert!(lru.order.is_empty(), "recency list must be cleared too");
        // Still usable, and the capacity accounting survived the clear.
        lru.insert(3, 30);
        assert_eq!(lru.get(&3), Some(&30));
    }

    fn tip(height: u64, hash: u8) -> ChainTip {
        ChainTip {
            height,
            hash: vec![hash; 32],
        }
    }

    /// The tx cache lives one block window: a re-observed identical tip keeps it, and ANY new
    /// hash clears it - including a greater height, because a reorg whose replacement chain is
    /// already longer is indistinguishable from an ordinary block at a tip poll, and a cached
    /// transaction's mined height may be wrong on the new chain.
    #[tokio::test]
    async fn any_tip_change_drops_the_transaction_cache() {
        let hub = ChainHub::new(test_server(), Duration::from_secs(1));
        let seed = || {
            hub.txs.lock().unwrap().insert(
                TxId::from_bytes([7; 32]),
                FetchedTx {
                    data: vec![1, 2, 3],
                    mined_height: Some(100),
                },
            )
        };
        seed();
        // Re-observing the identical tip (the TTL expired but no block arrived) keeps the cache.
        hub.note_tip(Some(&tip(100, 0xaa)), &tip(100, 0xaa));
        assert_eq!(hub.txs.lock().unwrap().len(), 1);
        // A new block - or a reorg observed at a greater height; the poll cannot tell - drops it.
        hub.note_tip(Some(&tip(100, 0xaa)), &tip(101, 0xbb));
        assert_eq!(hub.txs.lock().unwrap().len(), 0);
        seed();
        hub.note_tip(Some(&tip(100, 0xaa)), &tip(102, 0xcc));
        assert_eq!(hub.txs.lock().unwrap().len(), 0);
    }

    /// A tip that fails to extend the chain is a reorg: a cached transaction may now have a
    /// different mined height (or none), and callers store that height, so the cache is dropped.
    #[tokio::test]
    async fn non_extending_tip_drops_the_transaction_cache() {
        let hub = ChainHub::new(test_server(), Duration::from_secs(1));
        let seed = || {
            hub.txs.lock().unwrap().insert(
                TxId::from_bytes([7; 32]),
                FetchedTx {
                    data: vec![1, 2, 3],
                    mined_height: Some(100),
                },
            );
        };
        // Same height, different block: the tip was replaced.
        seed();
        hub.note_tip(Some(&tip(101, 0xaa)), &tip(101, 0xbb));
        assert_eq!(hub.txs.lock().unwrap().len(), 0);
        // A rollback to a lower height.
        seed();
        hub.note_tip(Some(&tip(101, 0xaa)), &tip(99, 0xcc));
        assert_eq!(hub.txs.lock().unwrap().len(), 0);
    }

    // ---------------------------------------------------------------------
    // Against a fake zebrad: the collapsing itself
    // ---------------------------------------------------------------------
    //
    // A minimal zebrad answering only what the hub's own paths touch, with a per-method call
    // counter. `chain::zebra`'s own tests carry the full fake (block conversion, auth, reorg);
    // this one exists to assert a different property - that N consumers produce one upstream
    // call - which needs counting, not fidelity.

    mod fake {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use std::sync::{Arc, Mutex};

        use axum::{extract::State, routing::post, Json, Router};
        use serde_json::{json, Value};

        #[derive(Default)]
        pub struct Calls(pub Mutex<HashMap<String, u32>>);

        impl Calls {
            pub fn count(&self, method: &str) -> u32 {
                *self.0.lock().unwrap().get(method).unwrap_or(&0)
            }
        }

        /// The txid the fake keeps in its mempool, and the only one `getrawtransaction` knows.
        pub const TXID_HEX: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";
        pub const BEST_HASH: &str =
            "2222222222222222222222222222222222222222222222222222222222222222";

        async fn handler(State(calls): State<Arc<Calls>>, Json(req): Json<Value>) -> Json<Value> {
            let method = req["method"].as_str().unwrap_or_default().to_string();
            *calls.0.lock().unwrap().entry(method.clone()).or_insert(0) += 1;
            let reply = |v: Value| Json(json!({ "result": v, "error": null, "id": "zecd" }));
            match method.as_str() {
                "getblockchaininfo" => reply(json!({
                    "chain": "main",
                    "blocks": 100,
                    "bestblockhash": BEST_HASH,
                })),
                "getbestblockhash" => reply(json!(BEST_HASH)),
                "z_getsubtreesbyindex" => reply(json!({
                    "subtrees": [{ "root": "33".repeat(32), "end_height": 90 }],
                })),
                "getrawmempool" => reply(json!([TXID_HEX])),
                // A one-byte body: the hub never parses it, it only moves the bytes around.
                "getrawtransaction" => reply(json!({ "hex": "00", "height": 100 })),
                other => Json(json!({
                    "result": null,
                    "error": { "code": -32601, "message": format!("Method not found: {other}") },
                    "id": "zecd"
                })),
            }
        }

        pub async fn serve() -> (SocketAddr, Arc<Calls>) {
            let calls = Arc::new(Calls::default());
            let app = Router::new()
                .route("/", post(handler))
                .with_state(Arc::clone(&calls));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            (addr, calls)
        }
    }

    /// Build a hub pointed at a fresh fake zebrad, plus `consumers` handles onto it - the
    /// daemon's shape with that many wallets.
    async fn hub_with_consumers(
        consumers: usize,
    ) -> (Arc<ChainHub>, Arc<fake::Calls>, Vec<HubSource>) {
        let (addr, calls) = fake::serve().await;
        let server = crate::backend::resolve(
            &format!("zebra://{}:{}", addr.ip(), addr.port()),
            crate::network::ZNetwork::Main,
        )
        .expect("loopback zebra endpoint resolves");
        let hub = ChainHub::new(server, Duration::from_secs(5));
        let mut sources = Vec::new();
        for _ in 0..consumers {
            sources.push(hub.acquire().await.expect("acquire from the fake"));
        }
        (hub, calls, sources)
    }

    /// The headline property: many wallets, one connection. Every consumer gets a working
    /// handle, but the endpoint is dialed once - which is also what makes `getblockchaininfo`
    /// (the zebra dial's liveness probe) fire once rather than once per wallet.
    #[tokio::test]
    async fn many_consumers_share_one_connection() {
        let (hub, calls, sources) = hub_with_consumers(50).await;
        assert_eq!(hub.stats().connects.load(Ordering::Relaxed), 1);
        assert_eq!(
            calls.count("getblockchaininfo"),
            1,
            "the dial's liveness probe must not repeat per consumer"
        );
        // All 50 handles are on the same generation, so a failure reported by any one of them
        // invalidates the connection they all share (exactly once).
        assert!(sources.iter().all(|s| s.generation() == 1));
    }

    /// N actors ticking on the same sync interval must cost one `getblockchaininfo`, not N.
    /// This is the poll that used to scale with the wallet count.
    #[tokio::test]
    async fn concurrent_tip_polls_collapse_to_one_upstream_call() {
        let (hub, calls, mut sources) = hub_with_consumers(20).await;
        let baseline = calls.count("getblockchaininfo");
        for source in &mut sources {
            let tip = source.latest_block().await.expect("tip");
            assert_eq!(tip.height, 100);
        }
        assert_eq!(
            calls.count("getblockchaininfo") - baseline,
            1,
            "20 tip polls inside the TTL are one upstream call"
        );
        assert_eq!(hub.stats().tip_fetches.load(Ordering::Relaxed), 1);
    }

    /// `server_info` is the wrong-chain guard's input and cannot change without a reconnect, and
    /// the subtree roots are the connect path's largest fixed cost (every root since activation).
    /// Both are per-connection, not per-wallet.
    #[tokio::test]
    async fn server_info_and_subtree_roots_are_fetched_once_per_connection() {
        let (hub, calls, mut sources) = hub_with_consumers(20).await;
        for source in &mut sources {
            let info = source.server_info().await.expect("server info");
            assert_eq!(info.chain_name, "main");
            let roots = source
                .subtree_roots(ShieldedPool::Sapling)
                .await
                .expect("subtree roots");
            assert_eq!(roots.len(), 1);
            assert_eq!(roots[0].completing_height, 90);
        }
        assert_eq!(hub.stats().server_info_fetches.load(Ordering::Relaxed), 1);
        assert_eq!(hub.stats().subtree_root_fetches.load(Ordering::Relaxed), 1);
        assert_eq!(calls.count("z_getsubtreesbyindex"), 1);
        // Sapling and Orchard are cached separately - one entry per pool, not one overall.
        sources[0]
            .subtree_roots(ShieldedPool::Orchard)
            .await
            .expect("orchard roots");
        assert_eq!(calls.count("z_getsubtreesbyindex"), 2);
    }

    /// Enhancement fetches one full transaction per wallet transaction, and in a fleet the same
    /// transaction is often relevant to many wallets. The bytes are identical, so it is fetched
    /// once and served from the cache thereafter.
    #[tokio::test]
    async fn a_transaction_relevant_to_many_wallets_is_fetched_once() {
        let (hub, calls, mut sources) = hub_with_consumers(20).await;
        let txid = TxId::from_bytes([0x11; 32]);
        for source in &mut sources {
            let tx = source
                .fetch_tx(txid)
                .await
                .expect("fetch")
                .expect("present");
            assert_eq!(tx.data, vec![0]);
            assert_eq!(tx.mined_height, Some(100));
        }
        assert_eq!(calls.count("getrawtransaction"), 1);
        assert_eq!(hub.stats().tx_fetches.load(Ordering::Relaxed), 1);
        assert_eq!(hub.stats().tx_cache_hits.load(Ordering::Relaxed), 19);
    }

    /// The worst of the per-wallet costs: the zebra mempool poller ticks every 2s *per wallet*,
    /// so a thousand wallets asked one zebrad for its mempool five hundred times a second. One
    /// subscription now serves everybody - and, critically, a consumer that subscribes after the
    /// stream opened is still replayed the transactions it missed, so it does not lose 0-conf
    /// visibility for the rest of the block.
    #[tokio::test]
    async fn many_wallets_share_one_mempool_subscription_with_replay() {
        let (hub, calls, mut sources) = hub_with_consumers(20).await;

        // The first subscriber opens the upstream stream.
        let mut first = sources[0].subscribe_mempool().await.expect("subscribe");
        let seen = first.message().await.expect("stream").expect("one tx");
        assert_eq!(seen.data, vec![0], "the mempool transaction's bytes");

        // Everyone else attaches to the same stream and is replayed what it already delivered.
        let mut others = Vec::new();
        for source in sources.iter_mut().skip(1) {
            others.push(source.subscribe_mempool().await.expect("subscribe"));
        }
        for (i, stream) in others.iter_mut().enumerate() {
            let replayed = stream
                .message()
                .await
                .expect("stream")
                .unwrap_or_else(|| panic!("late subscriber {i} must be replayed the mempool"));
            assert_eq!(replayed.data, vec![0]);
        }

        assert_eq!(
            hub.stats().mempool_subscriptions.load(Ordering::Relaxed),
            1,
            "20 wallets, one upstream subscription"
        );
        assert_eq!(
            calls.count("getrawmempool"),
            1,
            "and one getrawmempool for the whole fleet"
        );
    }

    /// A subscriber still holding an older generation joins the live pump rather than tearing
    /// it down. The invalidation that bumped the generation is hub bookkeeping - a stale
    /// handle's clone of the old connection may keep working, so it never reacquires - and if a
    /// mere generation *mismatch* reset the pump, one such handle would shut down the fresh
    /// subscription on every block and ping-pong with the reacquired handles forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_older_generation_subscriber_joins_rather_than_tears_down() {
        let (hub, _calls, mut sources) = hub_with_consumers(2).await;
        let mut stale = sources.remove(0); // generation 1

        // The connection fails and is replaced: the next acquire dials generation 2.
        hub.invalidate(stale.generation()).await;
        let mut fresh = hub.acquire().await.expect("re-acquire");
        assert!(fresh.generation() > stale.generation());

        // The fresh handle opens the shared pump...
        let mut fresh_stream = fresh.subscribe_mempool().await.expect("subscribe");
        let subs_after_fresh = hub.stats().mempool_subscriptions.load(Ordering::Relaxed);

        // ...and the stale handle attaches to it instead of superseding it.
        let mut stale_stream = stale.subscribe_mempool().await.expect("subscribe");
        assert_eq!(
            hub.stats().mempool_subscriptions.load(Ordering::Relaxed),
            subs_after_fresh,
            "the stale handle must join the live pump, not open (or reset to) its own"
        );
        let a = fresh_stream.message().await.expect("stream").expect("tx");
        let b = stale_stream.message().await.expect("stream").expect("tx");
        assert_eq!(a.data, b.data, "both handles read the same shared stream");
    }

    /// Reporting a failure against a superseded generation must not tear down the connection
    /// that already replaced it - otherwise one straggler's late error would knock over the
    /// healthy connection every other wallet just moved to.
    #[tokio::test]
    async fn invalidate_ignores_a_superseded_generation() {
        let hub = ChainHub::new(test_server(), Duration::from_secs(1));
        {
            let mut conn = hub.conn.lock().await;
            conn.generation = 5;
            // A stand-in for "there is a live connection"; `invalidate` only inspects the
            // generation and whether a source is present.
            conn.source = None;
        }
        hub.invalidate(4).await;
        assert_eq!(hub.conn.lock().await.generation, 5, "generation untouched");
    }
}
