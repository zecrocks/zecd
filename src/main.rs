//! `zecd` - a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash, built on librustzcash.

mod address;
mod amount;
mod backoff;
mod config;
mod error;
mod health;
mod init;
mod lightwalletd;
mod network;
mod rpc;
mod server;
mod socks;
mod state;
mod sync;
mod wallet;

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tracing::{error, info, warn};

use crate::config::{AppConfig, Cli, Command};
use crate::state::AppState;
use crate::wallet::actor::{self, ActorConfig};
use crate::wallet::store::WalletStore;
use crate::wallet::WalletRegistry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::resolve(&cli)?;
    init_tracing(&config.log);

    match &cli.command {
        Some(Command::Init(args)) => init::run(&config, args).await,
        _ => run_daemon(config).await,
    }
}

/// Initialize tracing. The filter defaults to `[log] level` and is overridden by `RUST_LOG`;
/// `[log] format = "json"` emits structured logs for cloud-native log aggregation.
fn init_tracing(log: &config::LogConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log.level));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if log.format.eq_ignore_ascii_case("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

async fn run_daemon(config: AppConfig) -> anyhow::Result<()> {
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
    for (name, entry) in &config.wallets {
        if !WalletStore::exists(&entry.dir) {
            warn!(
                "wallet '{}' is not initialized at {}; skipping (run `zecd init --wallet {}`)",
                name,
                entry.dir.display(),
                name
            );
            continue;
        }
        let servers = lightwalletd::resolve_all(
            &config.lightwalletd.servers,
            config.network,
            config.lightwalletd.tls_roots,
            config.lightwalletd.force_tls,
            config.lightwalletd.proxy,
        )?;
        let actor_cfg = ActorConfig {
            name: name.clone(),
            network: config.network,
            wallet_dir: entry.dir.clone(),
            servers,
            sync_interval: Duration::from_secs(config.sync.interval_secs),
            rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
            connect_timeout: Duration::from_secs(config.lightwalletd.connect_timeout_secs),
            reconnect_base: Duration::from_secs(config.lightwalletd.reconnect_base_secs),
            reconnect_max: Duration::from_secs(config.lightwalletd.reconnect_max_secs),
            primary_recheck: Duration::from_secs(config.lightwalletd.primary_recheck_secs),
            age_identity: config.keys.age_identity.clone(),
            auto_unlock: config.keys.auto_unlock,
            shutdown: shutdown_tx.subscribe(),
        };
        match actor::spawn(actor_cfg).await {
            Ok((handle, task)) => {
                info!("loaded wallet '{}'", name);
                registry.insert(handle);
                actor_tasks.push((name.clone(), task));
            }
            Err(e) => error!("failed to start wallet '{}': {e}", name),
        }
    }

    if registry.is_empty() {
        anyhow::bail!(
            "no usable wallets; run `zecd init` (datadir: {})",
            config.datadir.display()
        );
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
            Err(_) => warn!(
                "wallet '{name}' did not stop within {actor_stop_deadline:?}; exiting anyway"
            ),
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
