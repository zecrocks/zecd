//! Daemon wiring for the `zecd` binary: tracing init, wallet-actor spawning, the health and
//! RPC servers, and graceful shutdown.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::backend;
use crate::config::{self, AppConfig};
use crate::health;
use crate::server;
use crate::state::AppState;
use crate::wallet::actor::{self, ActorConfig};
use crate::wallet::store::WalletStore;
use crate::wallet::WalletRegistry;

/// Initialize tracing. The filter defaults to `[log] level` and is overridden by `RUST_LOG`;
/// `[log] format = "json"` emits structured logs for cloud-native log aggregation.
pub fn init_tracing(log: &config::LogConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log.level));
    // Log to stderr, not stdout: the `init`/`export-ufvk` CLI subcommands print machine-readable
    // output (the mnemonic, a UFVK) to stdout, and a log line on stdout would corrupt it.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if log.format.eq_ignore_ascii_case("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let prog = "zecd";
    // The example/deploy configs ship with a placeholder RPC password; on mainnet that is
    // spend authority, so refuse to start until it has been changed.
    if matches!(config.network, crate::network::ZNetwork::Main)
        && config
            .rpc
            .password
            .as_deref()
            .is_some_and(|p| p.trim().eq_ignore_ascii_case("change-me"))
    {
        anyhow::bail!(
            "[rpc] password is still the example placeholder \"CHANGE-ME\"; \
             set a real password before running on mainnet"
        );
    }
    actor::install_panic_hook();
    let config = Arc::new(config);
    let auth = server::auth::Authenticator::from_config(&config.rpc)?;

    // Shutdown broadcast: `true` is sent on Ctrl-C / `stop`. Created before the actors so
    // each one carries a receiver and can stop its sync loop between batches.
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut registry = WalletRegistry::new(config.default_wallet.clone());
    let mut actor_tasks = Vec::new();
    // zecd permits at most one wallet with spending keys; watch-only (UFVK) wallets may be
    // loaded without limit. Record each opened wallet's watch-only flag so the invariant can
    // be enforced once every wallet has been spawned (the flag is only known after the actor
    // reads the account from the wallet DB).
    let mut loaded: Vec<(String, bool)> = Vec::new();
    for (name, entry) in &config.wallets {
        if !WalletStore::exists(&entry.dir) {
            warn!(
                "wallet '{}' is not initialized at {}; skipping (run `{prog} init --wallet {}`)",
                name,
                entry.dir.display(),
                name
            );
            continue;
        }
        let mut server = backend::resolve(&config.backend.server, config.network)?;
        backend::apply_zebra_auth(&mut server, &config.zebra.auth());
        let actor_cfg = ActorConfig {
            name: name.clone(),
            network: config.network,
            wallet_dir: entry.dir.clone(),
            server,
            sync_interval: Duration::from_secs(config.sync.interval_secs),
            rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
            connect_timeout: Duration::from_secs(config.backend.connect_timeout_secs),
            reconnect_base: Duration::from_secs(config.backend.reconnect_base_secs),
            reconnect_max: Duration::from_secs(config.backend.reconnect_max_secs),
            age_identity: config.keys.age_identity.clone(),
            auto_unlock: config.keys.auto_unlock,
            // Validated at config load; re-derive here rather than carrying a second copy.
            confirmations_policy: config.spend.confirmations_policy()?,
            enabled_pools: entry.pools.clone(),
            default_receivers: entry.default_receivers.clone(),
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
                registry.insert(handle);
                actor_tasks.push((name.clone(), task));
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

    // Enforce the single-spending-wallet invariant before serving any RPC. A second spending
    // wallet is a misconfiguration the operator must resolve (zecd won't silently pick which
    // one is "the" spender), so this is fatal - the actors spawned above are torn down by the
    // shutdown signal sent on the early return.
    if let Err(e) = ensure_single_spending_wallet(&loaded) {
        shutdown_tx.send_replace(true);
        return Err(e);
    }

    let state = AppState {
        config: config.clone(),
        auth,
        registry: Arc::new(registry),
        started_at: Instant::now(),
        shutdown_tx: shutdown_tx.clone(),
        shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        work_queue: Arc::new(tokio::sync::Semaphore::new(config.rpc.work_queue)),
        active: crate::state::ActiveCommands::default(),
        operations: Arc::new(crate::operations::OperationRegistry::new()),
    };

    // Translate Ctrl-C into a graceful shutdown (flag first, so in-flight new requests 503).
    let ctrl_c_state = state.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("received Ctrl-C, shutting down");
            ctrl_c_state.trigger_shutdown();
        }
    });

    // Liveness/readiness probes on a separate port (best-effort; non-fatal if it can't bind).
    tokio::spawn(health::run(state.clone()));

    let result = server::run(state).await;

    // Stop the wallet actors and wait for them so the WalletDb is dropped cleanly rather than
    // the task being killed mid-write at runtime teardown. The send also covers the case where
    // `server::run` returned on its own (e.g. a bind error) without a shutdown trigger.
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

    // bitcoind removes its generated .cookie on clean shutdown so a stale credential can't
    // linger; do the same. Only applies when cookie auth was in use (no user/password set).
    if config.rpc.user.is_none() || config.rpc.password.is_none() {
        if let Some(cookie) = &config.rpc.cookiefile {
            match std::fs::remove_file(cookie) {
                Ok(()) => info!("removed cookie file {}", cookie.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("could not remove cookie file {}: {e}", cookie.display()),
            }
        }
    }
    result
}

/// Enforce zecd's single-spending-wallet rule: at most one loaded wallet may hold spending
/// keys, while any number of watch-only (UFVK) wallets may be loaded alongside it. `loaded`
/// pairs each successfully-opened wallet name with its watch-only flag (`true` = watch-only),
/// in a stable order so the error names the offending wallets deterministically. Returns an
/// error naming the two spending wallets when more than one is present.
fn ensure_single_spending_wallet(loaded: &[(String, bool)]) -> anyhow::Result<()> {
    let mut spenders = loaded
        .iter()
        .filter(|(_, watch_only)| !watch_only)
        .map(|(name, _)| name.as_str());
    if let (Some(first), Some(second)) = (spenders.next(), spenders.next()) {
        anyhow::bail!(
            "multiple spending wallets configured ('{first}' and '{second}'); zecd allows at \
             most one wallet with spending keys (any number of watch-only UFVK wallets may be \
             loaded alongside it). Convert one to watch-only (`zecd export-ufvk` + \
             `zecd init --ufvk`) or remove it from the configuration."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_single_spending_wallet;

    fn wallets(entries: &[(&str, bool)]) -> Vec<(String, bool)> {
        entries
            .iter()
            .map(|(name, watch_only)| (name.to_string(), *watch_only))
            .collect()
    }

    #[test]
    fn no_wallets_is_allowed() {
        // The empty case is guarded separately (registry.is_empty bail); the invariant check
        // itself must not error on it.
        assert!(ensure_single_spending_wallet(&[]).is_ok());
    }

    #[test]
    fn single_spending_wallet_is_allowed() {
        assert!(ensure_single_spending_wallet(&wallets(&[("default", false)])).is_ok());
    }

    #[test]
    fn only_watch_only_wallets_is_allowed() {
        // No spending wallet at all is fine (every wallet is a watch-only UFVK import).
        assert!(ensure_single_spending_wallet(&wallets(&[
            ("view-a", true),
            ("view-b", true),
            ("view-c", true),
        ]))
        .is_ok());
    }

    #[test]
    fn one_spending_plus_many_watch_only_is_allowed() {
        assert!(ensure_single_spending_wallet(&wallets(&[
            ("default", false),
            ("view-a", true),
            ("view-b", true),
        ]))
        .is_ok());
    }

    #[test]
    fn two_spending_wallets_are_rejected() {
        let err = ensure_single_spending_wallet(&wallets(&[("default", false), ("second", false)]))
            .expect_err("two spending wallets must be rejected");
        let msg = err.to_string();
        // The error names both offenders so the operator knows which to convert/remove.
        assert!(msg.contains("'default'"), "{msg}");
        assert!(msg.contains("'second'"), "{msg}");
        assert!(msg.contains("at most one"), "{msg}");
    }

    #[test]
    fn two_spending_wallets_mixed_with_watch_only_are_rejected() {
        // Watch-only wallets interleaved with the spenders don't mask the violation; the first
        // two spenders in order are named.
        let err = ensure_single_spending_wallet(&wallets(&[
            ("view-a", true),
            ("spend-a", false),
            ("view-b", true),
            ("spend-b", false),
        ]))
        .expect_err("two spending wallets must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("'spend-a'"), "{msg}");
        assert!(msg.contains("'spend-b'"), "{msg}");
    }
}
