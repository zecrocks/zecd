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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

use anyhow::Context as _;

use crate::backend;
use crate::chain;
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

        // The `[spend]` values a SIGHUP reload can change while running. One cell, shared by
        // every actor, so a reload reaches all of them at once - and read per send rather than
        // copied into each actor, so it takes effect on the next send instead of the next
        // restart. See `crate::config::SpendLimits`.
        let spend_limits = crate::config::SpendLimits::new(&config.spend);

        let registry = WalletRegistry::new(config.default_wallet.clone());
        let mut actor_tasks = Vec::new();
        // Warm the Orchard proving keys once (they're wallet-independent; the Zakura stack
        // caches them process-wide, and the fused builder reads the same cells) and share the
        // handle across every actor, so the first send finds them built and their prepared
        // commitment tables armed. On by default (`[spend] cache_proving_key`).
        //
        // The keygen runs **in the background**: it is seconds of CPU, and only sends need its
        // result, so blocking here would delay spawning the actors (and, in the daemon, binding
        // the health and RPC listeners) - leaving the node unreachable and not syncing for the
        // whole window. The first send awaits `ProvingKeys::get`; by then it is normally long
        // finished.
        // ...but only where a send is possible at all. A daemon whose every wallet is
        // watch-only - a `[fleet]` of view wallets, or `init --ufvk` replicas - cannot sign a
        // transaction, so warming and arming these keys spends startup CPU and holds the armed
        // commitment tables resident for something nothing in the process can reach. This is the
        // same cut the actor already makes one level down, where a watch-only actor builds no
        // Sapling prover.
        let spender_present = any_wallet_can_spend(&config.wallets);
        let orchard_keys = if config.spend.cache_proving_key && spender_present {
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
        } else if config.spend.cache_proving_key {
            // Not `None`: the handle still builds on demand (`ProvingKeys::get` is a
            // `OnceCell::get_or_try_init`), so a send that arrives anyway - a wallet this
            // predicate read as watch-only, or one added by a future runtime path - still
            // proves, paying the warm-up inline exactly as a send arriving before the
            // background task would. Skipping the *eager* warm-up is the whole change; it
            // cannot make a send fail.
            info!(
                "no wallet holds spending keys; not warming the Orchard proving keys (they build \
                 on demand if a send ever arrives)"
            );
            Some(actor::ProvingKeys::new(
                config
                    .network
                    .activation_height(NetworkUpgrade::Nu6_3)
                    .is_some(),
            ))
        } else {
            None
        };
        // The upstream connections this daemon holds, keyed by endpoint - see the hub comment in
        // the wallet loop below. A wallet joins an existing hub when its resolved endpoint matches
        // one already dialed, so the common single-backend deployment holds exactly one.
        let mut hubs: HashMap<String, Arc<chain::hub::ChainHub>> = HashMap::new();

        // Validated at config load; re-derive once rather than carrying a second copy. Shared
        // by the configured wallets and the fleet's shards.
        let confirmations_policy = match config.spend.confirmations_policy() {
            Ok(policy) => policy,
            Err(e) => {
                stop_actors(&shutdown_tx, actor_tasks).await;
                return Err(e);
            }
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
            // One shared upstream per distinct endpoint (`chain::hub`). Wallets used to dial
            // individually, so a daemon's upstream load - connections, chain-tip polls and, worst,
            // the 2s mempool poll - scaled with the wallet count rather than with the chain.
            // Wallets resolve their own endpoint (a `[wallets.<name>]` may override the global
            // `[backend]`), so the hubs are keyed by that endpoint: every wallet agreeing on the
            // dial shares one connection, and a wallet pointed somewhere else gets its own.
            let hub = Arc::clone(hubs.entry(server.connection_key()).or_insert_with(|| {
                chain::hub::ChainHub::new(
                    server.clone(),
                    Duration::from_secs(config.backend.connect_timeout_secs),
                )
            }));
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
            let actor_cfg = ActorConfig {
                name: name.clone(),
                // The wallet's own chain rather than the daemon-global network: the actor is
                // configured entirely from its entry, so nothing below this point reads
                // `config` again.
                network: entry.zcash_network(),
                engine_dir: entry.engine_dir(),
                keys_path: keys_path.clone(),
                hub: Arc::clone(&hub),
                sync_interval: Duration::from_secs(config.sync.interval_secs),
                rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
                fetch_memos: config.sync.fetch_memos,
                batch_size: config.sync.batch_size,
                writer_cache_mib: config.sync.writer_cache_mib,
                reconnect_base: Duration::from_secs(config.backend.reconnect_base_secs),
                reconnect_max: Duration::from_secs(config.backend.reconnect_max_secs),
                age_identity: config.keys.age_identity.clone(),
                auto_unlock: config.keys.auto_unlock,
                bootstrap: config.keys.bootstrap_from_keys,
                confirmations_policy,
                spend_limits: spend_limits.clone(),
                target_note_count: config.spend.target_note_count,
                min_split_output_value: config.spend.min_split_output_value,
                orchard_keys: orchard_keys.clone(),
                pipeline_proving: config.spend.pipeline_proving,
                shutdown_drain: Duration::from_secs(config.spend.shutdown_drain_secs),
                trust_own_transactions: config.spend.trust_own_transactions,
                enabled_pools: entry.pools.clone(),
                default_receivers: entry.default_receivers.clone(),
                transparent_enabled: entry.transparent_enabled,
                transparent_default: entry.transparent_default,
                transparent_gap_limit: entry.transparent_gap_limit,
                transparent_initial_scan: entry.transparent_initial_scan,
                transparent_allow_beyond_recovery_window: entry
                    .transparent_allow_beyond_recovery_window,
                transparent_gap_warn_threshold: entry.transparent_gap_warn_threshold,
                // Configured wallets are conventional single-wallet actors; the fleet's shard
                // actors are spawned separately below.
                shard_members: Vec::new(),
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

        // Fleet shards come from manifests rather than `[wallets.<name>]`, so they carry no
        // per-wallet `[backend]` override and ride the daemon's global endpoint - sharing a hub
        // with any configured wallet that resolves to the same place. Constructing it is free
        // when there is no fleet: a hub does not dial until something acquires a source.
        let fleet_hub = {
            let server = match backend::resolve_configured(&config) {
                Ok(server) => server,
                Err(e) => {
                    stop_actors(&shutdown_tx, actor_tasks).await;
                    return Err(e);
                }
            };
            Arc::clone(hubs.entry(server.connection_key()).or_insert_with(|| {
                chain::hub::ChainHub::new(
                    server.clone(),
                    Duration::from_secs(config.backend.connect_timeout_secs),
                )
            }))
        };

        // The fleet: many watch-only wallets scanned in a handful of shards rather than one
        // actor apiece. Additive - with no manifests present this does nothing, and the
        // `[wallets.<name>]` actors above are untouched.
        let fleet = match spawn_fleet(
            &config,
            &fleet_hub,
            confirmations_policy,
            &spend_limits,
            &shutdown_tx,
            &registry,
            &mut actor_tasks,
        )
        .await
        {
            Ok(fleet) => fleet,
            Err(e) => {
                stop_actors(&shutdown_tx, actor_tasks).await;
                return Err(e);
            }
        };

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
        if let Err(e) = crate::daemon::ensure_single_spending_wallet(
            &loaded,
            config.keys.allow_multiple_spending_wallets,
        ) {
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
            fleet: fleet.clone(),
            spend_limits,
        };

        Ok(Node {
            state,
            actor_tasks,
            _datadir_lock: Some(self.datadir_lock),
        })
    }
}

/// Spawn the fleet: one shard actor per group of manifested view wallets, each serving all of
/// its members from a single scan. Returns how many wallets were registered.
///
/// The shape is deliberately the same as the configured-wallet loop above - resolve, spawn,
/// register - with two differences that are the whole point of a shard: one `spawn_shard` call
/// produces *many* handles, and the wallets it serves come from the manifest directory rather
/// than from the config file, so onboarding does not mean editing config.
///
/// Additive: with no manifests present this returns 0 without touching anything.
#[allow(clippy::too_many_arguments)]
async fn spawn_fleet(
    config: &AppConfig,
    hub: &Arc<chain::hub::ChainHub>,
    confirmations_policy: zcash_client_backend::data_api::wallet::ConfirmationsPolicy,
    spend_limits: &crate::config::SpendLimits,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    registry: &WalletRegistry,
    actor_tasks: &mut Vec<(String, tokio::task::JoinHandle<()>)>,
) -> anyhow::Result<Option<Arc<crate::fleet::FleetManager>>> {
    // Experimental and opt-in: with `[fleet] enabled` false (the default) the manifest
    // directory is never read, no shard is opened, and `state.fleet` stays `None`, which is
    // what makes the wallet-management RPCs refuse. Checked before the directory read so a
    // stray file in the datadir cannot enrol a daemon that never asked for a fleet.
    if !config.fleet.enabled {
        return Ok(None);
    }
    let (members, skipped) = crate::fleet::load_manifests(&config.fleet.manifest_dir)?;
    for skip in &skipped {
        warn!(
            "fleet manifest {} is not being served: {}",
            skip.path.display(),
            skip.reason
        );
    }
    // Past the gate, no manifests is an *empty* fleet, not an absent one: the manager is still
    // built (it is only data - nothing dials or spawns until a wallet exists) so `createwallet`
    // can onboard the first fleet wallet at runtime. Returning `None` for an empty directory
    // would leave the RPC that exists to avoid config-file-and-restart onboarding unable to
    // bootstrap on exactly the daemons that have not bootstrapped yet. `None` means "this
    // operator did not ask for a fleet", which is the check above, and nothing else.
    // A fleet wallet name must not collide with a configured one: both are addressed as
    // `/wallet/<name>`, and a collision would silently route one of them to the other's actor.
    for member in &members {
        if config.wallets.contains_key(&member.name) {
            anyhow::bail!(
                "fleet wallet '{}' collides with the configured [wallets.{}] entry: both would \
                 be served at /wallet/{}. Rename one of them.",
                member.name,
                member.name,
                member.name
            );
        }
    }

    // Where each already-imported wallet lives, read back from the shard databases themselves -
    // there is no placement file to fall out of step with reality. Opening each shard read-only
    // also tells us how full it is, which is what placement needs.
    let shard_dirs = crate::fleet::existing_shard_dirs(&config.fleet.dir);
    let mut placed = std::collections::BTreeMap::new();
    let mut existing = Vec::with_capacity(shard_dirs.len());
    for (index, dir) in shard_dirs.iter().enumerate() {
        let state =
            crate::fleet::inspect_shard(config.network, config.fleet.coin, dir, index, &mut placed)
                .with_context(|| format!("inspecting shard {}", dir.display()))?;
        existing.push(state);
    }

    let layout = crate::fleet::plan(members, &placed, &existing, &config.fleet);
    let total = layout.members();
    // The manager keeps the pieces a shard actor is built from, so `createwallet` can place a
    // wallet into a running shard - or open a new one - without a restart.
    let manager = Arc::new(crate::fleet::FleetManager::new(
        config.fleet.clone(),
        crate::fleet::ShardTemplate {
            network: config.network,
            coin: config.fleet.coin,
            hub: Arc::clone(hub),
            sync_interval: Duration::from_secs(config.sync.interval_secs),
            rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
            fetch_memos: config.sync.fetch_memos,
            batch_size: config.sync.batch_size,
            writer_cache_mib: config.sync.writer_cache_mib,
            reconnect_base: Duration::from_secs(config.backend.reconnect_base_secs),
            reconnect_max: Duration::from_secs(config.backend.reconnect_max_secs),
            confirmations_policy,
            spend_limits: spend_limits.clone(),
            target_note_count: config.spend.target_note_count,
            min_split_output_value: config.spend.min_split_output_value,
            enabled_pools: config.pools.enabled.clone(),
            default_receivers: config.pools.default_receivers.clone(),
            shutdown: shutdown_tx.clone(),
        },
    ));
    for (dir, members) in layout.shards {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating shard directory {}", dir.display()))?;
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("shard")
            .to_string();
        let actor_cfg = ActorConfig {
            name: name.clone(),
            network: config.network,
            engine_dir: crate::config::shard_engine_dir(&dir, config.fleet.coin),
            // A shard has no keys.toml: its wallets are watch-only accounts imported from the
            // manifest's viewing keys, so there is no seed, passphrase or bootstrap involved.
            // The path still points at the shard root, where a wallet's would sit - above the
            // engine directory, which nothing but librustzcash owns.
            keys_path: dir.join("keys.toml"),
            hub: Arc::clone(hub),
            sync_interval: Duration::from_secs(config.sync.interval_secs),
            rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
            fetch_memos: config.sync.fetch_memos,
            batch_size: config.sync.batch_size,
            writer_cache_mib: config.sync.writer_cache_mib,
            reconnect_base: Duration::from_secs(config.backend.reconnect_base_secs),
            reconnect_max: Duration::from_secs(config.backend.reconnect_max_secs),
            age_identity: None,
            auto_unlock: false,
            bootstrap: false,
            confirmations_policy,
            spend_limits: spend_limits.clone(),
            // Carried for completeness: a shard member never spends, so the change-splitting
            // knobs are never consulted. Taking the configured values rather than defaults keeps
            // a shard actor's config identical to a wallet actor's on every field it shares.
            target_note_count: config.spend.target_note_count,
            min_split_output_value: config.spend.min_split_output_value,
            // Shard members never spend, so the proving keys are dead weight here.
            orchard_keys: None,
            pipeline_proving: false,
            // Nor is there anything to drain: a shard actor accepts no sends.
            shutdown_drain: Duration::ZERO,
            // Never consulted either: the trust marker is written at send-store time.
            trust_own_transactions: false,
            enabled_pools: config.pools.enabled.clone(),
            default_receivers: config.pools.default_receivers.clone(),
            // Shielded-only: the transparent matcher keeps per-account gap windows, pre-exposure
            // progress and recovery horizons, and generalizing those to K accounts is its own
            // piece of work.
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: config.pools.transparent_gap_limit,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: true,
            transparent_gap_warn_threshold: config.pools.transparent_gap_warn_threshold,
            shard_members: members,
            shutdown: shutdown_tx.subscribe(),
        };
        let member_names: Vec<String> = actor_cfg
            .shard_members
            .iter()
            .map(|m| m.name.clone())
            .collect();
        let lowest_birthday = actor_cfg
            .shard_members
            .iter()
            .map(|m| u32::from(m.birthday))
            .min();
        let (handles, task) = actor::spawn_shard(actor_cfg)
            .await
            .with_context(|| format!("starting fleet shard '{name}'"))?;
        // Any of this shard's handles serves as the prototype for a member onboarded into it
        // later: they differ only by name.
        if let Some(prototype) = handles.first().cloned() {
            manager.register_shard(dir.clone(), prototype, member_names, lowest_birthday);
        }
        for handle in handles {
            registry.insert(CoinWallet::Zcash(handle));
        }
        actor_tasks.push((name, task));
    }
    if total > 0 {
        info!(
            "fleet: {total} view wallet(s) across {} shard(s)",
            shard_count(&manager)
        );
    }
    Ok(Some(manager))
}

/// How many shards the manager currently tracks (for the startup line).
/// Whether any configured wallet could ever sign a transaction - i.e. whether this daemon has
/// any use for the Orchard proving keys.
///
/// Reads `keys.toml`, not the wallet database. A `zecd init --ufvk` wallet is seedless by
/// construction (`WalletStore::init_view_only`), and `keys.toml` is written before the database
/// exists, so this is answerable at startup - before any actor has spawned and reported the
/// `watch_only` flag the single-spender invariant later uses. An *encrypted* wallet still holds
/// its seed as ciphertext, so a locked spender counts as a spender without decrypting anything.
///
/// Fleet shards are deliberately not consulted: a manifest carries a viewing key and nothing
/// else, so a shard member can never spend (`wallet/shard.rs` imports it watch-only).
///
/// An unreadable or absent `keys.toml` counts as **spending**. Both directions are safe - the
/// keys build on demand either way - but being wrong this way costs one eager warm-up, where
/// being wrong the other way costs a send its warm-up latency, and this is also the reading
/// that leaves a misconfigured datadir behaving exactly as it does today.
fn any_wallet_can_spend(
    wallets: &std::collections::BTreeMap<String, crate::config::WalletEntry>,
) -> bool {
    wallets
        .values()
        .any(|entry| keys_file_can_spend(&entry.keys_path()))
}

/// The per-wallet half of [`any_wallet_can_spend`]: whether the `keys.toml` at this path holds
/// spending material.
fn keys_file_can_spend(keys_path: &std::path::Path) -> bool {
    if !WalletStore::exists(keys_path) {
        return true;
    }
    match WalletStore::read(keys_path) {
        Ok(store) => store.has_seed(),
        Err(_) => true,
    }
}

fn shard_count(manager: &crate::fleet::FleetManager) -> usize {
    manager.shards()
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

/// Where one wallet's librustzcash database is, and which account in it is that wallet's.
///
/// Both halves are needed to call [`crate::wallet::read`] against a running node's wallet, and
/// neither was reachable before: a wallet's engine directory is computable from
/// [`crate::config::WalletEntry::engine_dir`] only for a configured `[wallets.<name>]` entry,
/// and a fleet member has no such entry - its account lives in a shard directory the config
/// layer knows nothing about. See [`Node::wallet_location`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct WalletLocation {
    /// The directory holding this wallet's `data.sqlite`, as [`crate::wallet::read`] takes it.
    /// Shared with the rest of a shard for a fleet member.
    pub engine_dir: std::path::PathBuf,
    /// This wallet's account, or `None` while it does not exist yet (a wallet awaiting its
    /// bootstrap, or a fleet member awaiting import - `waitforsync`'s `imported` tells them
    /// apart).
    pub account: Option<crate::AccountUuid>,
    /// The scope to hand [`crate::wallet::read::query_transactions`] and its siblings. Not
    /// derivable from `account` alone: a `None` account means "every account in this database"
    /// for a conventional wallet, whose database holds none, and "no account" for a fleet member
    /// awaiting import, whose database holds its shard-mates'.
    pub scope: crate::wallet::read::AccountScope,
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
    /// Where `wallet`'s database is and which account in it to read, for an embedder querying
    /// [`crate::wallet::read`] directly instead of going through [`Node::call`].
    ///
    /// `wallet` names the wallet as the HTTP `/wallet/<name>` segment does, `None` meaning the
    /// default; an unknown name is the usual `-18`. This is the only supported route to a
    /// **fleet** member's files, whose shard directory no config helper can produce.
    ///
    /// The account is `None` in the window before it exists, which is why the scope is reported
    /// beside it rather than left for the caller to derive - the two `None` cases scope
    /// differently (see [`WalletLocation::scope`]).
    pub fn wallet_location(&self, wallet: Option<&str>) -> Result<WalletLocation, RpcError> {
        let handle = self.state.registry.get(wallet)?;
        Ok(WalletLocation {
            engine_dir: handle.engine_dir.clone(),
            account: handle.account(),
            scope: handle.account_scope(),
        })
    }

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

    /// Apply a freshly resolved configuration to this running node.
    ///
    /// Only the keys on [`crate::config::RELOADABLE_KEYS`] take effect; every other difference
    /// is reported as needing a restart rather than being silently dropped. The returned report
    /// says exactly what changed and what did not, which is what the caller logs - an operator
    /// who edits a key that cannot be reloaded needs to be told, not left to infer it from
    /// behaviour that did not change.
    ///
    /// This exists for the Orchard-action cap: a wallet whose notes have fragmented fails every
    /// send until the cap moves, and restarting a live payment wallet to change a number is a
    /// poor answer. The cap is deliberately not reachable from RPC - it bounds what one call
    /// can make the daemon prove, so its raise channel must require process-level authority.
    /// The binary wires this to SIGHUP; an embedder calls it directly.
    pub fn reload_config(&self, fresh: &AppConfig) -> crate::config::ReloadReport {
        crate::config::apply_reload(&self.state.config, fresh, &self.state.spend_limits)
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
        // Shard actors started *after* boot (a `createwallet` that opened a new shard) are owned
        // by the fleet manager, not by this list. They must be awaited too, or the process could
        // exit with one of them mid-write - the exact thing awaiting the boot-time actors exists
        // to prevent.
        let mut tasks = self.actor_tasks;
        if let Some(fleet) = &self.state.fleet {
            tasks.extend(fleet.take_tasks());
        }
        // The send inside covers the case where the embedder never called `trigger_shutdown`.
        stop_actors(&self.state.shutdown_tx, tasks).await;
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
        let config = walletless_config_with_safelist(allowed_methods);
        Node::for_tests(AppState {
            config: Arc::new(config),
            registry: Arc::new(WalletRegistry::new("default".into())),
            started_at: Instant::now(),
            shutdown_tx: tokio::sync::watch::channel(false).0,
            shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            work_queue: Arc::new(tokio::sync::Semaphore::new(16)),
            active: crate::state::ActiveCommands::default(),
            operations: Arc::new(crate::operations::OperationRegistry::new()),
            fleet: None,
            spend_limits: crate::config::SpendLimits::new(&crate::config::SpendConfig::default()),
        })
    }

    /// A node serving exactly one wallet, built from a [`crate::wallet::WalletHandle::for_test`]
    /// handle: no actor, no database, only the registry lookups and the fields the handle
    /// publishes. Enough for the accessors that read a handle without dispatching.
    pub(crate) fn node_with_test_wallet(
        name: &str,
        status: crate::wallet::SyncStatus,
        is_shard: bool,
    ) -> Node {
        let node = walletless_node();
        let handle = crate::wallet::WalletHandle::for_test(name, crate::network::regtest(), status);
        let handle = if is_shard {
            handle.into_shard_for_test()
        } else {
            handle
        };
        node.state
            .registry
            .insert(crate::wallet::CoinWallet::Zcash(handle));
        node
    }

    /// The resolved config behind [`walletless_node`], for tests that check a *policy* over a
    /// config rather than dispatch behaviour.
    pub(crate) fn walletless_config() -> AppConfig {
        walletless_config_with_safelist(vec![])
    }

    fn walletless_config_with_safelist(allowed_methods: Vec<String>) -> AppConfig {
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
        AppConfig {
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
                proxy: None,
            },
            zebra: Default::default(),
            fleet: Default::default(),
            rpc,
            keys: KeysConfig {
                age_identity: None,
                auto_unlock: true,
                bootstrap_from_keys: true,
                allow_multiple_spending_wallets: false,
            },
            sync: SyncConfig {
                interval_secs: 20,
                rebroadcast_secs: 60,
                fetch_memos: true,
                batch_size: crate::sync::engine::DEFAULT_BATCH_SIZE,
                writer_cache_mib: crate::wallet::open::DEFAULT_WRITER_CACHE_MIB,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::testutil::{
        node_with_test_wallet, walletless_node as test_node,
        walletless_node_with_safelist as test_node_with_safelist,
    };

    /// `wallet_location` is the only supported route to a fleet member's database, so it has to
    /// answer three ways, and the third is the one the config helpers cannot express: an account
    /// that does not exist *yet* in a database that holds other wallets' accounts.
    #[test]
    fn wallet_location_reports_the_account_and_the_scope_it_implies() {
        use crate::wallet::read::AccountScope;
        use crate::wallet::SyncStatus;
        use std::sync::Arc;
        use zcash_client_sqlite::AccountUuid;

        // Imported: the account, and a scope naming it.
        let account = AccountUuid::from_uuid(uuid::Uuid::from_u128(7));
        let status = SyncStatus {
            accounts: Arc::new([("w".to_string(), account)].into_iter().collect()),
            ..Default::default()
        };
        let node = node_with_test_wallet("w", status, true);
        let loc = node.wallet_location(Some("w")).expect("a loaded wallet");
        assert_eq!(loc.account, Some(account));
        assert_eq!(loc.scope, AccountScope::Only(account));

        // A conventional wallet awaiting its bootstrap: no account, and the database holds none,
        // so every account in it is the same as this wallet's - the pre-fleet scope.
        let node = node_with_test_wallet("w", SyncStatus::default(), false);
        let loc = node.wallet_location(Some("w")).expect("a loaded wallet");
        assert_eq!(loc.account, None);
        assert_eq!(loc.scope, AccountScope::Any);

        // A shard member awaiting import: also no account, but its database is its shard's, so
        // the same `None` must scope to nothing instead. This is why the scope is reported
        // rather than left for the caller to derive from `account`.
        let node = node_with_test_wallet("w", SyncStatus::default(), true);
        let loc = node.wallet_location(Some("w")).expect("a loaded wallet");
        assert_eq!(loc.account, None);
        assert_eq!(loc.scope, AccountScope::NoAccount);
    }

    /// An unknown wallet is the same `-18` the RPC path gives, so a caller handles one error for
    /// both seams.
    #[test]
    fn wallet_location_rejects_an_unknown_wallet() {
        let node = test_node();
        let err = node
            .wallet_location(Some("nope"))
            .expect_err("no such wallet");
        assert_eq!(err.code, crate::error::codes::RPC_WALLET_NOT_FOUND);
    }

    /// The check that decides whether to warm the Orchard proving keys reads `keys.toml`, so it
    /// must answer for a watch-only wallet (seedless, `init --ufvk`) and a spending one - and,
    /// the case that matters most, for anything it cannot read, which has to count as spending
    /// so an unexpected datadir keeps today's behaviour rather than quietly losing the warm-up.
    #[test]
    fn only_a_seedless_keys_file_skips_the_proving_key_warmup() {
        use crate::wallet::store::WalletStore;
        use zcash_protocol::consensus::BlockHeight;

        // The committed testnet development phrase (valueless) - a deterministic spending seed.
        const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
                              midnight culture idea mountain fame park social drip bid doctor \
                              scatter glance defy moment stage";
        // Stored verbatim by `init_view_only` and never parsed here, so an obvious placeholder
        // is better than a real-looking key nobody can verify (as in `store.rs`'s own tests).
        const UFVK: &str = "uviewtest1nodeplaceholder";

        let dir = tempfile::tempdir().expect("tempdir");
        let net = crate::network::regtest();

        let seedless = dir.path().join("view-only.toml");
        WalletStore::init_view_only(&seedless, BlockHeight::from_u32(1), net, UFVK)
            .expect("write a seedless keys.toml");
        assert!(
            !super::keys_file_can_spend(&seedless),
            "a seedless wallet cannot sign, so nothing needs the proving keys"
        );

        // An encrypted spender still counts: the seed is present as ciphertext, so this decides
        // without unlocking anything.
        let encrypted = dir.path().join("encrypted.toml");
        let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(PHRASE).expect("phrase");
        WalletStore::init_with_passphrase(
            &encrypted,
            crate::wallet::store::Passphrase::from("correct horse battery".to_string()),
            &mnemonic,
            BlockHeight::from_u32(1),
            net,
            UFVK,
        )
        .expect("write an encrypted keys.toml");
        assert!(
            super::keys_file_can_spend(&encrypted),
            "a locked spending wallet is still a spending wallet"
        );

        // A `keys.toml` that is not there at all: the wallet loop warns and skips such a wallet,
        // but reading its absence as watch-only would be inferring custody from a missing file.
        assert!(
            super::keys_file_can_spend(&dir.path().join("does-not-exist.toml")),
            "an absent keys.toml must not be read as watch-only"
        );

        // Likewise one that does not parse.
        let corrupt = dir.path().join("corrupt.toml");
        std::fs::write(&corrupt, b"this is not toml at all").expect("write");
        assert!(
            super::keys_file_can_spend(&corrupt),
            "an unreadable keys.toml must not be read as watch-only"
        );
    }

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
