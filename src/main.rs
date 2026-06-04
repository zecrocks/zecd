//! `zecd` - a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash, built on librustzcash.

mod address;
mod amount;
mod config;
mod error;
mod init;
mod lightwalletd;
mod rpc;
mod server;
mod state;
mod sync;
mod wallet;

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use tokio::sync::Notify;
use tracing::{error, info, warn};

use crate::config::{AppConfig, Cli, Command};
use crate::state::AppState;
use crate::wallet::actor::{self, ActorConfig};
use crate::wallet::store::WalletStore;
use crate::wallet::WalletRegistry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let config = AppConfig::resolve(&cli)?;

    match &cli.command {
        Some(Command::Init(args)) => init::run(&config, args).await,
        _ => run_daemon(config).await,
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn run_daemon(config: AppConfig) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let auth = server::auth::Authenticator::from_config(&config.rpc)?;

    let mut registry = WalletRegistry::new(config.default_wallet.clone());
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
        let server = lightwalletd::resolve(&config.lightwalletd.server, config.network)?;
        let actor_cfg = ActorConfig {
            name: name.clone(),
            network: config.network,
            wallet_dir: entry.dir.clone(),
            server,
            sync_interval: Duration::from_secs(config.sync.interval_secs),
            age_identity: config.keys.age_identity.clone(),
            auto_unlock: config.keys.auto_unlock,
        };
        match actor::spawn(actor_cfg).await {
            Ok(handle) => {
                info!("loaded wallet '{}'", name);
                registry.insert(handle);
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

    let shutdown = Arc::new(Notify::new());
    let state = AppState {
        config: config.clone(),
        auth,
        registry: Arc::new(registry),
        started_at: Instant::now(),
        shutdown: shutdown.clone(),
    };

    // Translate Ctrl-C into a graceful shutdown.
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("received Ctrl-C, shutting down");
            shutdown.notify_one();
        }
    });

    server::run(state).await
}
