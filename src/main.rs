//! `zecd` - a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash.

use clap::Parser;

use zecd::config::{AppConfig, Cli, Command};
use zecd::daemon::{self, DaemonOptions};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::resolve(&cli)?;
    daemon::init_tracing(&config.log);

    match &cli.command {
        Some(Command::Init(args)) => zecd::init::run(&config, args).await,
        Some(Command::ExportUfvk(args)) => zecd::init::export_ufvk(&config, args),
        _ => daemon::run(config, DaemonOptions::zecd()).await,
    }
}
