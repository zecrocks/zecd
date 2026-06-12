//! `tparty` - transparent Zcash deposit addresses that auto-shield.
//!
//! A Bitcoin-Core-style JSON-RPC server (same library, auth, and wire format as `zecd`)
//! whose `getnewaddress` returns transparent t-addresses. Every deposit received on them is
//! automatically moved into the same seed's shielded pool - the account's internal Orchard
//! receiver, which any librustzcash wallet restoring the seed scans by default - as soon as
//! it reaches the configured confirmation depth. The addresses it hands out can never
//! collide with `zecd`'s: zecd issues Orchard-only unified addresses (external scope),
//! tparty issues P2PKH t-addresses and shields to the internal scope.

use clap::{CommandFactory, FromArgMatches};
use zcash_protocol::value::Zatoshis;

use zecd::config::{AppConfig, Cli, Command, TPARTY_DEFAULTS};
use zecd::daemon::{self, DaemonOptions};
use zecd::state::Dispatcher;
use zecd::wallet::actor::AutoShield;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Reuse zecd's CLI surface under the `tparty` program name (clap's derive pins the name,
    // so rebind it before parsing for correct help/usage/error text).
    let matches = Cli::command()
        .name("tparty")
        .about(
            "transparent Zcash deposit addresses that auto-shield into the wallet's shielded pool",
        )
        .get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    let config = AppConfig::resolve_with(&cli, &TPARTY_DEFAULTS)?;
    daemon::init_tracing(&config.log);

    match &cli.command {
        Some(Command::Init(args)) => zecd::init::run(&config, args).await,
        _ => {
            let t = &config.tparty;
            let opts = DaemonOptions {
                prog: "tparty",
                dispatcher: Dispatcher::Tparty,
                auto_shield: Some(AutoShield {
                    pool: t.pool,
                    min_conf: t.min_conf,
                    threshold: Zatoshis::from_u64(t.threshold_zat).map_err(|_| {
                        anyhow::anyhow!("[tparty] threshold_zat exceeds the maximum money supply")
                    })?,
                }),
                gap_limit: Some(t.gap_limit),
            };
            daemon::run(config, opts).await
        }
    }
}
