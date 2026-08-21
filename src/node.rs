//! Embedding zecd in another process: build a running node (wallet actors, registry,
//! async-operation registry, proving keys) without the HTTP RPC or health servers, and
//! dispatch RPCs in-process with wire-identical semantics.
//!
//! The `zecd` binary is this facade plus the HTTP layers: [`crate::daemon::run`] is
//! `NodeBuilder::prepare` + the HTTP `Authenticator` + `PreparedNode::start` + the health and
//! RPC servers + signal handling. An embedder that wants only the node stops at
//! [`NodeBuilder::start`] and talks to it through [`Node::call`].
//!
//! Two things the facade deliberately does NOT do:
//! - It never constructs a [`crate::server::auth::Authenticator`]: auth belongs to the HTTP
//!   transport, and `Authenticator::from_config` writes a cookie file as a side effect.
//! - It never calls [`crate::hardening::harden_process`]: disabling core dumps and ptrace is
//!   process-global policy, the host application's decision, so only the binary applies it.
//!
//! A multi-thread tokio runtime is required: the scan and proving paths use
//! `tokio::task::block_in_place`, which panics on a current-thread runtime.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

use crate::backend;
use crate::config::{self, AppConfig};
use crate::error::RpcError;
use crate::state::AppState;
use crate::wallet::actor::{self, ActorConfig};
use crate::wallet::binding;
use crate::wallet::store::WalletStore;
use crate::wallet::{CoinWallet, WalletRegistry};

/// Builder for an embedded zecd node. `new(config).start().await` is the normal entry point;
/// the two-phase `prepare()` / [`PreparedNode::start`] split exists so the binary can run its
/// HTTP-only startup work (building the RPC `Authenticator`, logging the auth mode) between
/// the fail-fast checks and the wallet spawns, preserving the daemon's exact startup order.
pub struct NodeBuilder {
    config: AppConfig,
}

impl NodeBuilder {
    pub fn new(config: AppConfig) -> NodeBuilder {
        NodeBuilder { config }
    }

    /// Phase 1 - everything that must fail before any wallet is touched: take the exclusive
    /// datadir lock (a second zecd on the same datadir would corrupt the wallet DB), refuse a
    /// placeholder RPC password, and install the (idempotent) panic hook.
    pub fn prepare(self) -> anyhow::Result<PreparedNode> {
        // Single-instance guard: take the exclusive datadir lock before opening any wallet, and
        // hold it for the node's whole lifetime (the guard rides on the `Node`). See `crate::lock`.
        let datadir_lock = crate::lock::lock_datadir(&self.config.datadir)?;
        // The example/deploy configs ship with a placeholder RPC password; on mainnet that is
        // spend authority, so refuse to start until it has been changed. Shared with
        // `zecd config check`, which reports the same refusal without starting anything.
        config::reject_placeholder_password(&self.config)?;
        actor::install_panic_hook();
        Ok(PreparedNode {
            config: Arc::new(self.config),
            datadir_lock,
        })
    }

    /// `prepare()` + [`PreparedNode::start`] in one call - the normal embedding entry point.
    pub async fn start(self) -> anyhow::Result<Node> {
        self.prepare()?.start().await
    }
}

/// A node that has passed the fail-fast checks ([`NodeBuilder::prepare`]) but has not yet
/// spawned any wallet actor. The binary builds its HTTP `Authenticator` at this point.
pub struct PreparedNode {
    config: Arc<AppConfig>,
    datadir_lock: fmutex::Guard<'static>,
}

impl PreparedNode {
    /// The resolved configuration (the binary reads it to build the HTTP `Authenticator`
    /// between `prepare()` and `start()`).
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Phase 2: migrate the data-directory layout if needed, kick off the background
    /// proving-key builds, spawn one actor per initialized wallet, enforce the
    /// single-spending-wallet invariant, and assemble the shared state.
    ///
    /// A failed account-to-keys binding check ([`binding::BindingMismatch`]) is fatal for the
    /// whole node - evidence the wallet database or `keys.toml` was replaced - while any other
    /// per-wallet startup failure (unreadable database, missing files) skips just that wallet.
    ///
    /// On a fatal error, any actors already spawned are signalled and *awaited* before the
    /// error returns. The error drops the datadir lock, so no actor may still be writing the
    /// wallet DB at that point: an embedder that fixes its config and retries in-process must
    /// not be able to reacquire the lock over a straggler. (The binary never noticed - a fatal
    /// startup error exits the process - but the facade outlives its errors.)
    pub async fn start(self) -> anyhow::Result<Node> {
        let prog = "zecd";
        let config = self.config;

        // Move any librustzcash file still sitting at a wallet directory's root into that
        // wallet's per-coin engine subdirectory, before anything opens a wallet. Runs under the
        // datadir lock taken in `prepare()`, is a no-op on an already-migrated (or brand new)
        // data directory, and is fatal when it cannot complete: the data is still there, and
        // starting without it would rebuild an empty database beside it. See `crate::migrate`.
        crate::migrate::migrate(&config)?;

        // Shutdown broadcast: `true` is sent on shutdown. Created before the actors so each one
        // carries a receiver and can stop its sync loop between batches.
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let mut registry = WalletRegistry::new(config.default_wallet.clone());
        let mut actor_tasks = Vec::new();
        // Build the Orchard proving keys once (they're wallet-independent) and share them across
        // every actor, so each send reuses the cached key instead of rebuilding it per transaction.
        // On by default (`[spend] cache_proving_key`).
        //
        // The keygen runs **in the background**: it is seconds of CPU, and only sends need its
        // result, so blocking here would delay spawning the actors (and, in the daemon, binding
        // the health and RPC listeners) - leaving the node unreachable and not syncing for the
        // whole window. The first send awaits `ProvingKeys::get`; by then it is normally long
        // finished.
        let orchard_keys = if config.spend.cache_proving_key {
            // Also build the PostNu6_3 (Ironwood) proving key when this network can activate
            // NU6.3, so post-NU6.3 sends prove the Ironwood bundle from the cache instead of
            // rebuilding a key per send. NU6.3 is live on mainnet (3_428_143) and testnet
            // (4_134_000), so both build it; only a regtest chain without
            // `ZECD_REGTEST_NU63_HEIGHT` skips a keygen no send there could use.
            let build_ironwood = config
                .network
                .activation_height(NetworkUpgrade::Nu6_3)
                .is_some();
            info!(
                "building Orchard proving key{} in the background (cached for all sends)",
                if build_ironwood {
                    " + Ironwood (PostNu6_3) proving key"
                } else {
                    ""
                }
            );
            let keys = actor::ProvingKeys::new(build_ironwood);
            keys.spawn_build();
            Some(keys)
        } else {
            None
        };
        // zecd permits at most one wallet with spending keys; watch-only (UFVK) wallets may be
        // loaded without limit. Record each opened wallet's watch-only flag so the invariant can
        // be enforced once every wallet has been spawned (the flag is only known after the actor
        // reads the account from the wallet DB).
        let mut loaded: Vec<(String, bool)> = Vec::new();
        for (name, entry) in &config.wallets {
            let keys_path = entry.keys_path();
            if !WalletStore::exists(&keys_path) {
                warn!(
                    "wallet '{}' is not initialized ({} missing); skipping (run `{prog} init --wallet {}`)",
                    name,
                    keys_path.display(),
                    name
                );
                continue;
            }
            let server = match backend::resolve_for_wallet(&config, entry) {
                Ok(server) => server,
                Err(e) => {
                    stop_actors(&shutdown_tx, actor_tasks).await;
                    return Err(e);
                }
            };
            // Transparent *receives* now ride the block scan on both backends, so a large address
            // set no longer means per-block polling. What stays per-address is spend detection:
            // librustzcash emits one `TransactionsInvolvingAddress` request per funded address, and
            // on a light backend each is a remote round trip rather than a local index lookup. A
            // wallet holding many funded transparent addresses is therefore still better served by
            // a local zebra - worth saying once at startup, before the scan begins.
            const LIGHT_TRANSPARENT_ADDR_WARN: u32 = 1_000;
            if server.kind() == backend::ServerKind::Lightwalletd
                && entry.transparent_enabled
                && (entry.transparent_initial_scan >= LIGHT_TRANSPARENT_ADDR_WARN
                    || entry.transparent_gap_limit >= LIGHT_TRANSPARENT_ADDR_WARN)
            {
                // This runs before the wallet's actor (and its `wallet` span) exists, so the
                // wallet identity is a field here rather than span context.
                tracing::warn!(
                    wallet = %name,
                    "transparent_initial_scan = {} / transparent_gap_limit = {} on a \
                     lightwalletd backend: spend detection queries each funded address separately, \
                     one remote round trip apiece. Running your own zebra (server = \"zebra\") is \
                     recommended at this scale",
                    entry.transparent_initial_scan,
                    entry.transparent_gap_limit,
                );
            }
            // Validated at config load; re-derive here rather than carrying a second copy.
            let confirmations_policy = match config.spend.confirmations_policy() {
                Ok(policy) => policy,
                Err(e) => {
                    stop_actors(&shutdown_tx, actor_tasks).await;
                    return Err(e);
                }
            };
            let actor_cfg = ActorConfig {
                name: name.clone(),
                // The wallet's own chain rather than the daemon-global network: the actor is
                // configured entirely from its entry, so nothing below this point reads
                // `config` again.
                network: entry.zcash_network(),
                engine_dir: entry.engine_dir(),
                keys_path: keys_path.clone(),
                server,
                sync_interval: Duration::from_secs(config.sync.interval_secs),
                rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
                connect_timeout: Duration::from_secs(config.backend.connect_timeout_secs),
                reconnect_base: Duration::from_secs(config.backend.reconnect_base_secs),
                reconnect_max: Duration::from_secs(config.backend.reconnect_max_secs),
                age_identity: config.keys.age_identity.clone(),
                auto_unlock: config.keys.auto_unlock,
                bootstrap: config.keys.bootstrap_from_keys,
                confirmations_policy,
                orchard_action_limit: config.spend.orchard_action_limit,
                orchard_keys: orchard_keys.clone(),
                pipeline_proving: config.spend.pipeline_proving,
                enabled_pools: entry.pools.clone(),
                default_receivers: entry.default_receivers.clone(),
                transparent_enabled: entry.transparent_enabled,
                transparent_default: entry.transparent_default,
                transparent_gap_limit: entry.transparent_gap_limit,
                transparent_initial_scan: entry.transparent_initial_scan,
                transparent_allow_beyond_recovery_window: entry
                    .transparent_allow_beyond_recovery_window,
                transparent_gap_warn_threshold: entry.transparent_gap_warn_threshold,
                shutdown: shutdown_tx.subscribe(),
            };
            match actor::spawn(actor_cfg).await {
                Ok((handle, task)) => {
                    let watch_only = handle.status().watch_only;
                    info!(
                        "loaded wallet '{}'{}",
                        name,
                        if watch_only { " (watch-only)" } else { "" }
                    );
                    loaded.push((name.clone(), watch_only));
                    registry.insert(CoinWallet::Zcash(handle));
                    actor_tasks.push((name.clone(), task));
                }
                // A failed account-to-keys binding check is evidence the wallet database (or
                // keys.toml) was replaced, so it is fatal for the whole node, like the
                // single-spending-wallet invariant: zecd won't quietly keep serving the other
                // wallets while one of them shows signs of tampering. Any other per-wallet
                // startup failure (unreadable database, missing files) skips just that wallet.
                Err(e) if e.downcast_ref::<binding::BindingMismatch>().is_some() => {
                    stop_actors(&shutdown_tx, actor_tasks).await;
                    return Err(e);
                }
                Err(e) => error!("failed to start wallet '{}': {e}", name),
            }
        }

        if registry.is_empty() {
            anyhow::bail!(
                "no usable wallets; run `{prog} init` (datadir: {})",
                config.datadir.display()
            );
        }

        // Enforce the single-spending-wallet invariant before serving anything. A second spending
        // wallet is a misconfiguration the operator must resolve (zecd won't silently pick which
        // one is "the" spender), so this is fatal - the actors spawned above are stopped and
        // awaited before the error releases the datadir lock.
        if let Err(e) = crate::daemon::ensure_single_spending_wallet(&loaded) {
            stop_actors(&shutdown_tx, actor_tasks).await;
            return Err(e);
        }

        let state = AppState {
            config: config.clone(),
            registry: Arc::new(registry),
            started_at: Instant::now(),
            shutdown_tx: shutdown_tx.clone(),
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            work_queue: Arc::new(tokio::sync::Semaphore::new(config.rpc.work_queue)),
            active: crate::state::ActiveCommands::default(),
            operations: Arc::new(crate::operations::OperationRegistry::new()),
        };

        Ok(Node {
            state,
            actor_tasks,
            _datadir_lock: Some(self.datadir_lock),
        })
    }
}

/// Signal shutdown and wait for the given actor tasks, so no task is still writing the wallet
/// DB when the caller releases the datadir lock. Shared by [`Node::shutdown`] and the fatal
/// paths of [`PreparedNode::start`]; the per-actor deadline matches the daemon's historical
/// teardown.
async fn stop_actors(
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    actor_tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
) {
    shutdown_tx.send_replace(true);
    let actor_stop_deadline = Duration::from_secs(30);
    for (name, task) in actor_tasks {
        match tokio::time::timeout(actor_stop_deadline, task).await {
            Ok(_) => info!("wallet '{name}' stopped"),
            Err(_) => {
                warn!("wallet '{name}' did not stop within {actor_stop_deadline:?}; exiting anyway")
            }
        }
    }
}

/// The per-call knobs of [`Node::send`], defaulting to what the Bitcoin-dialect sends do: the
/// wallet's configured confirmations policy, its configured `[spend] privacy_policy`, and no
/// named funding source. `SendOptions::default()` is therefore the plain "pay this request"
/// call, and each field is the in-process spelling of one `z_sendmany` argument.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Minimum confirmations for note selection (`z_sendmany`'s `minconf`), applied as a
    /// symmetric override of the wallet's policy. `None` uses the configured policy. Values
    /// below 1 are served as 1: a shielded note is never spendable at 0 confirmations.
    pub minconf: Option<u32>,
    /// The privacy policy for this send (`z_sendmany`'s `privacyPolicy`). `None` uses the
    /// wallet's configured `[spend] privacy_policy`. The ladder is enforced identically to the
    /// RPC path, including the authoritative re-check on the built proposal.
    pub privacy: Option<crate::config::SendPrivacy>,
    /// The funding source (`z_sendmany`'s `fromaddress`). Defaults to
    /// [`crate::wallet::SendSource::Unspecified`] - shielded notes, no coin control.
    pub source: crate::wallet::SendSource,
}

/// A running embedded zecd node: the wallet actors, registry, and async-operation registry,
/// behind the same dispatch table the HTTP server uses. Owns the datadir lock for its
/// lifetime; call [`Node::shutdown`] to stop the actors and release it cleanly.
pub struct Node {
    state: AppState,
    actor_tasks: Vec<(String, tokio::task::JoinHandle<()>)>,
    // `None` only for the test constructor; production nodes always hold the datadir lock.
    _datadir_lock: Option<fmutex::Guard<'static>>,
}

impl Node {
    /// Dispatch one RPC with wire-identical semantics: the same dispatch table, the same
    /// `[rpc] allowed_methods` safelist, the same positional-arity checks, and the same error
    /// codes as an HTTP call. `wallet` plays the role of the HTTP `/wallet/<name>` path
    /// segment (`None` = the default wallet).
    ///
    /// Differences from the HTTP transport are transport-level only: there is no auth, no
    /// work-queue bound (callers control their own concurrency), and no 503-on-shutdown gate -
    /// after [`Node::trigger_shutdown`] a call behaves as dispatch behaves (the `waitfor*`
    /// family returns promptly on the shutdown signal). Note `stop` is regtest-only and
    /// triggers this node's shutdown, exactly as it does over HTTP.
    pub async fn call(
        &self,
        wallet: Option<&str>,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, RpcError> {
        let req = crate::server::jsonrpc::RpcRequest::positional(method, params);
        // Register with the in-flight tracker so `getrpcinfo` sees embedded calls too.
        let _active = self.state.active.begin(&req.method);
        // Same `rpc` span the HTTP transport enters, so an embedded call's downstream events
        // are attributable exactly as an HTTP one's are - and so an embedder's own span
        // wrapping this call nests zecd's events underneath it (the correlation id they can
        // attach, which zecd deliberately has no field for).
        use tracing::Instrument as _;
        let span = tracing::info_span!(
            "rpc",
            method = %req.method,
            wallet = wallet.unwrap_or("default")
        );
        crate::rpc::dispatch(&self.state, wallet, &req)
            .instrument(span)
            .await
    }

    /// Build, prove, and broadcast a send from a caller-constructed ZIP-321 transaction
    /// request - the memo-native send seam for embedders, and part of the supported library
    /// surface (see the crate root).
    ///
    /// [`Node::call`] can reach every send RPC, but only through their zcashd/Bitcoin-dialect
    /// argument shapes: a JSON array of `{address, amount, memo}` objects that zecd parses back
    /// into exactly this type. A consumer that already holds a [`TransactionRequest`] - anything
    /// building payments programmatically, memo-carrying protocols above all - would otherwise
    /// have to render one to JSON for zecd to re-parse. Everything below this method is the RPC
    /// path unchanged: the same single-writer actor, so sends still serialize and cannot
    /// double-spend; the same privacy ladder; the same `SendSource` one-source-per-send rule.
    ///
    /// Two differences from `z_sendmany` are worth knowing:
    ///
    /// - **Duplicate recipients are accepted.** A [`TransactionRequest`] may pay one address
    ///   from several payments, and nothing in consensus or the wallet forbids two shielded
    ///   outputs to one address - it is how a batch of memos to a single address is written in
    ///   one transaction, for one fee. `z_sendmany` refuses it for zcashd parity (relaxable with
    ///   `[rpc] allow_duplicate_shielded_recipients`); this seam never had that check to relax.
    /// - **It is synchronous.** `z_sendmany` returns an opid and proves on a detached task;
    ///   this awaits the send and returns the txid, so there is no operation to poll and
    ///   nothing lost if the process restarts (the async-operation registry is in-memory).
    ///
    /// Errors are the RPC errors, unchanged - `-18` for an unknown wallet, `-6` for
    /// insufficient funds, `-4` for a policy refusal - so an embedder branching on
    /// [`RpcError::code`] reads the same codes an HTTP caller does.
    pub async fn send(
        &self,
        wallet: Option<&str>,
        request: zip321::TransactionRequest,
        opts: SendOptions,
    ) -> Result<zcash_protocol::TxId, RpcError> {
        // Resolve exactly as dispatch does, so an unknown wallet is the same `-18` here as over
        // the wire, and a non-Zcash wallet (when a second engine lands) fails at the same
        // single-arm match rather than in the send path.
        let handle = self.state.registry.get(wallet)?;
        // Visible to `getrpcinfo` like any dispatched call. Named for the seam rather than for
        // an RPC method, since no wire method is being served.
        let _active = self.state.active.begin("node::send");
        let span = tracing::info_span!(
            "rpc",
            method = "node::send",
            wallet = wallet.unwrap_or("default")
        );
        use tracing::Instrument as _;
        handle
            .send(
                request,
                opts.minconf
                    .map(crate::rpc::wallet_methods::symmetrical_confirmations),
                opts.privacy.unwrap_or(self.state.config.spend.privacy),
                opts.source,
            )
            .instrument(span)
            .await
    }

    /// Request graceful shutdown (what `stop` and the daemon's SIGINT/SIGTERM handling do):
    /// wallet actors stop their sync loops between batches and blocking `waitfor*` calls
    /// unblock. Await [`Node::shutdown`] to wait for the actors afterwards.
    pub fn trigger_shutdown(&self) {
        self.state.trigger_shutdown();
    }

    /// A future that resolves once shutdown has been requested (also immediately when it
    /// already was) - the embedder's `select!` peer, like the daemon's servers.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        self.state.shutdown_signal()
    }

    /// Stop the wallet actors and wait for them, so the wallet DB is dropped cleanly rather
    /// than the tasks being killed mid-write at runtime teardown. Consumes the node; the
    /// datadir lock is released on return.
    pub async fn shutdown(self) {
        // The send inside covers the case where the embedder never called `trigger_shutdown`.
        stop_actors(&self.state.shutdown_tx, self.actor_tasks).await;
    }

    /// The shared state, for the binary's HTTP layers (`server::run`, `health::run`).
    #[cfg(feature = "server")]
    pub(crate) fn app_state(&self) -> &AppState {
        &self.state
    }

    /// A node over a hand-built state - no datadir lock, no actors - so dispatch semantics can
    /// be pinned without a wallet or an upstream.
    #[cfg(test)]
    pub(crate) fn for_tests(state: AppState) -> Node {
        Node {
            state,
            actor_tasks: Vec::new(),
            _datadir_lock: None,
        }
    }
}

/// Test-only builders shared with the typed-client tests: a walletless node over a
/// hand-built state, so dispatch semantics can be pinned without a wallet or an upstream.
#[cfg(test)]
pub(crate) mod testutil {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Instant;

    use super::Node;
    use crate::config::{AppConfig, BackendConfig, KeysConfig, RpcConfig, SyncConfig};
    use crate::state::AppState;
    use crate::wallet::WalletRegistry;

    /// A node over a state with no wallets and the default (empty) safelist, mirroring the
    /// server tests' builder.
    pub(crate) fn walletless_node() -> Node {
        walletless_node_with_safelist(vec![])
    }

    pub(crate) fn walletless_node_with_safelist(allowed_methods: Vec<String>) -> Node {
        let rpc = RpcConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 1,
            user: Some("u".into()),
            password: Some("p".into()),
            auth: vec![],
            cookiefile: None,
            work_queue: 16,
            allowed_methods,
            allow_duplicate_shielded_recipients: false,
        };
        let config = AppConfig {
            network: crate::network::ZNetwork::Test,
            datadir: std::path::PathBuf::from("/tmp"),
            default_wallet: "default".into(),
            wallets: BTreeMap::new(),
            backend: BackendConfig {
                server: crate::config::DEFAULT_SERVER.into(),
                connect_timeout_secs: 10,
                reconnect_base_secs: 1,
                reconnect_max_secs: 60,
                rfc1918_is_local: true,
                allow_remote_cleartext: false,
                tls: None,
                tls_roots: Default::default(),
                tls_insecure_skip_verify: false,
                tls_ca_pem: None,
                tls_ca_file: None,
                tls_pins: Vec::new(),
                assume_transparent_in_compact_blocks: false,
            },
            zebra: Default::default(),
            rpc,
            keys: KeysConfig {
                age_identity: None,
                auto_unlock: true,
                bootstrap_from_keys: true,
            },
            sync: SyncConfig {
                interval_secs: 20,
                rebroadcast_secs: 60,
            },
            spend: crate::config::SpendConfig::default(),
            pools: crate::config::PoolsConfig::default(),
            health: crate::config::HealthConfig {
                enabled: false,
                bind: "127.0.0.1".parse().unwrap(),
                port: 9233,
                readiness: crate::config::ReadinessMode::Connected,
                max_scan_lag: 4,
            },
            log: crate::config::LogConfig {
                level: "info".into(),
                format: "text".into(),
            },
        };
        Node::for_tests(AppState {
            config: Arc::new(config),
            registry: Arc::new(WalletRegistry::new("default".into())),
            started_at: Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            work_queue: Arc::new(tokio::sync::Semaphore::new(16)),
            active: crate::state::ActiveCommands::default(),
            operations: Arc::new(crate::operations::OperationRegistry::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::testutil::{
        walletless_node as test_node, walletless_node_with_safelist as test_node_with_safelist,
    };

    /// `call` runs the same dispatch table as HTTP: a method that does not exist is -32601,
    /// with the same message shape.
    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let node = test_node();
        let err = node
            .call(None, "definitely_not_a_method", vec![])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_METHOD_NOT_FOUND);
    }

    /// The positional-arity bound applies to embedded calls exactly as over HTTP: Bitcoin
    /// Core's help error (-1) with the same message.
    #[tokio::test]
    async fn over_arity_calls_are_rejected() {
        let node = test_node();
        let err = node
            .call(None, "uptime", vec![Value::from("x")])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_MISC_ERROR);
        assert!(
            err.message.contains("takes at most 0 argument(s)"),
            "{}",
            err.message
        );
    }

    /// A non-empty `[rpc] allowed_methods` safelist binds embedded calls too - the facade is
    /// wire-identical, not a bypass. A blocked real method reads as method-not-found.
    #[tokio::test]
    async fn allowed_methods_safelist_applies() {
        let node = test_node_with_safelist(vec!["uptime".into()]);
        assert!(node.call(None, "uptime", vec![]).await.is_ok());
        let err = node.call(None, "getnetworkinfo", vec![]).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_METHOD_NOT_FOUND);
    }

    /// Wallet resolution is the registry's, same as `/wallet/<name>` routing: with no wallet
    /// loaded, a wallet method fails -18 rather than panicking or inventing a wallet.
    #[tokio::test]
    async fn wallet_methods_fail_wallet_not_found_without_wallets() {
        let node = test_node();
        let err = node.call(None, "getblockcount", vec![]).await.unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_NOT_FOUND);
        let err = node
            .call(Some("nope"), "getwalletinfo", vec![])
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_NOT_FOUND);
    }

    /// `send` resolves its wallet through the same registry lookup dispatch uses, so an unknown
    /// or absent wallet is the identical `-18` a `z_sendmany` over the wire would return -
    /// rather than a panic, or a different error taxonomy for the in-process seam.
    #[tokio::test]
    async fn send_resolves_wallets_exactly_as_dispatch_does() {
        let node = test_node();
        let request = zip321::TransactionRequest::empty();

        for wallet in [None, Some("nope")] {
            let err = node
                .send(wallet, request.clone(), super::SendOptions::default())
                .await
                .unwrap_err();
            assert_eq!(
                err.code,
                crate::error::codes::RPC_WALLET_NOT_FOUND,
                "wallet {wallet:?} must fail resolution the way dispatch does"
            );
            // Same message shape as the wire path, so an embedder's logs read identically.
            let dispatched = node
                .call(wallet, "getwalletinfo", vec![])
                .await
                .unwrap_err();
            assert_eq!(err.message, dispatched.message);
        }
    }

    /// Plain control methods answer without any wallet or upstream.
    #[tokio::test]
    async fn control_methods_answer_offline() {
        let node = test_node();
        let uptime = node.call(None, "uptime", vec![]).await.unwrap();
        assert!(uptime.is_u64());
        let help = node.call(None, "help", vec![]).await.unwrap();
        assert!(help.as_str().unwrap().contains("zecd"));
    }
}
