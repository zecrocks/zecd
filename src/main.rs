//! `zecd` - a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash.

use clap::Parser;

use zecd::config::{AppConfig, Cli, Command};
use zecd::daemon;

// musl's default allocator is ~5-6x slower than glibc's under Orchard proving's multi-threaded
// allocation churn. Both musl release images
// build with `--features mimalloc-secure` to close that gap (the `mimalloc` feature, plus
// MI_SECURE heap hardening); native glibc builds leave it off (parity either way, so it would be
// pure dependency weight). The hardening is a compile-time flag of the mimalloc crate, so the
// global allocator declaration is identical for both `mimalloc` and `mimalloc-secure`.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // `rpcauth` is a pure credential generator - it needs no datadir, config file, or wallet,
    // so handle it before resolving config (which can refuse e.g. a placeholder mainnet setup).
    if let Some(Command::Rpcauth(args)) = &cli.command {
        return zecd::server::auth::run_rpcauth(args);
    }

    let config = AppConfig::resolve(&cli)?;
    daemon::init_tracing(&config.log);
    // Disable core dumps + ptrace before any seed is decrypted (best-effort; see hardening).
    zecd::hardening::harden_process();

    match &cli.command {
        Some(Command::Init(args)) => zecd::init::run(&config, args).await,
        Some(Command::ExportUfvk(args)) => zecd::init::export_ufvk(&config, args),
        _ => daemon::run(config).await,
    }
}
