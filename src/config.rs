//! Daemon configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].
//!
//! CLI flags use Bitcoin-Core-style names (`-rpcuser`, `-rpcport`, `-datadir`, `-testnet`)
//! where it helps operators, but the canonical source is the TOML config.
#![allow(dead_code)] // some config fields/helpers are part of the model but not yet read

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use clap::Parser;
use serde::Deserialize;
use zcash_protocol::consensus::Network;

/// Default lightwalletd endpoint: the public zecrocks infrastructure
/// (`zec.rocks:443` on mainnet, `testnet.zec.rocks:443` on testnet). Self-hosted
/// deployments override `[lightwalletd] server` with their local node.
pub const DEFAULT_LIGHTWALLETD: &str = "zecrocks";

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub network: Network,
    pub datadir: PathBuf,
    pub default_wallet: String,
    pub wallets: BTreeMap<String, WalletEntry>,
    pub lightwalletd: LightwalletdConfig,
    pub rpc: RpcConfig,
    pub keys: KeysConfig,
    pub sync: SyncConfig,
    pub health: HealthConfig,
    pub log: LogConfig,
}

#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Serve liveness/readiness probes on a separate, unauthenticated HTTP port.
    pub enabled: bool,
    pub bind: IpAddr,
    pub port: u16,
    /// Scan progress at/above which `/readyz` reports ready (0..=1).
    pub ready_progress: f64,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Default tracing filter (overridden by `RUST_LOG`).
    pub level: String,
    /// "text" (human) or "json" (structured, for log aggregation).
    pub format: String,
}

#[derive(Debug, Clone)]
pub struct WalletEntry {
    pub name: String,
    pub dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct LightwalletdConfig {
    /// `ecc` | `ywallet` | `zecrocks` | a comma-separated `host:port` list.
    pub server: String,
    /// `direct` | `tor` | `socks5://host:port`.
    pub connection: String,
    /// TLS root certificates to trust (`native` or `webpki`).
    pub tls_roots: crate::lightwalletd::TlsRoots,
    /// Force TLS on/off; `None` = auto (TLS for remote hosts, plaintext for localhost).
    pub force_tls: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Path to a bitcoind-style cookie file; generated at startup when no user/password set.
    pub cookiefile: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct KeysConfig {
    /// age identity file used to decrypt the wallet seed for unattended sending.
    pub age_identity: Option<PathBuf>,
    /// When true, decrypt the seed at startup so sends need no `walletpassphrase`.
    pub auto_unlock: bool,
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub interval_secs: u64,
}

impl AppConfig {
    /// Look up a wallet by name, or the default wallet when `name` is `None`.
    pub fn wallet(&self, name: Option<&str>) -> Option<&WalletEntry> {
        let name = name.unwrap_or(&self.default_wallet);
        self.wallets.get(name)
    }

    /// Default RPC port for a network when none is configured (zcashd convention).
    pub fn default_rpc_port(network: Network) -> u16 {
        match network {
            Network::MainNetwork => 8232,
            Network::TestNetwork => 18232,
        }
    }
}

// ---------------------------------------------------------------------------
// On-disk TOML representation
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    network: Option<String>,
    datadir: Option<PathBuf>,
    default_wallet: Option<String>,
    #[serde(default)]
    wallets: BTreeMap<String, WalletFile>,
    lightwalletd: Option<LightwalletdFile>,
    rpc: Option<RpcFile>,
    keys: Option<KeysFile>,
    sync: Option<SyncFile>,
    health: Option<HealthFile>,
    log: Option<LogFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthFile {
    enabled: Option<bool>,
    bind: Option<String>,
    port: Option<u16>,
    ready_progress: Option<f64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogFile {
    level: Option<String>,
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LightwalletdFile {
    server: Option<String>,
    connection: Option<String>,
    tls_roots: Option<String>,
    tls: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcFile {
    bind: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    cookiefile: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    age_identity: Option<PathBuf>,
    auto_unlock: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncFile {
    interval_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// `zecd` - a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash.
#[derive(Debug, Parser)]
#[command(name = "zecd", version)]
pub struct Cli {
    /// Path to the TOML config file (default: <datadir>/zecd.toml, else ./zecd.toml).
    #[arg(long, value_name = "FILE")]
    pub conf: Option<PathBuf>,

    /// Data directory holding per-wallet subdirectories and the cookie file.
    #[arg(long, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// Use testnet (overrides config `network`).
    #[arg(long)]
    pub testnet: bool,

    /// Network: "main" or "test".
    #[arg(long, value_name = "NET")]
    pub network: Option<String>,

    /// RPC bind address.
    #[arg(long = "rpcbind", value_name = "ADDR")]
    pub rpc_bind: Option<String>,

    /// RPC port.
    #[arg(long = "rpcport", value_name = "PORT")]
    pub rpc_port: Option<u16>,

    /// RPC username (HTTP Basic auth).
    #[arg(long = "rpcuser", value_name = "USER")]
    pub rpc_user: Option<String>,

    /// RPC password (HTTP Basic auth).
    #[arg(long = "rpcpassword", value_name = "PASS")]
    pub rpc_password: Option<String>,

    /// lightwalletd server: ecc | ywallet | zecrocks | host:port[,host:port].
    #[arg(long, value_name = "SERVER")]
    pub server: Option<String>,

    /// age identity file used to decrypt the wallet seed for sending.
    #[arg(long, value_name = "FILE", env = "ZECD_AGE_IDENTITY")]
    pub age_identity: Option<PathBuf>,

    /// Subcommand. When omitted, runs the daemon.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Create and initialize a new wallet (mnemonic + accounts), then exit.
    Init(InitArgs),
    /// Run the JSON-RPC daemon (default).
    Run,
}

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Wallet name (selects/creates <datadir>/<name>).
    #[arg(long, default_value = "default")]
    pub wallet: String,

    /// Human-readable account name stored in the wallet.
    #[arg(long, default_value = "primary")]
    pub account_name: String,

    /// Restore from an existing mnemonic instead of generating a new one (read from stdin).
    #[arg(long)]
    pub restore: bool,

    /// Optional birthday height; defaults to the current chain tip for new wallets.
    #[arg(long)]
    pub birthday: Option<u32>,
}

fn parse_network(s: &str) -> anyhow::Result<Network> {
    match s.trim() {
        "main" | "mainnet" => Ok(Network::MainNetwork),
        "test" | "testnet" => Ok(Network::TestNetwork),
        other => Err(anyhow!("unsupported network: {other}")),
    }
}

impl AppConfig {
    /// Resolve the effective configuration from CLI flags and the TOML file.
    pub fn resolve(cli: &Cli) -> anyhow::Result<AppConfig> {
        let datadir = cli
            .datadir
            .clone()
            .or_else(|| std::env::var_os("ZECD_DATADIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("./zecd-data"));

        let conf_path = cli
            .conf
            .clone()
            .unwrap_or_else(|| datadir.join("zecd.toml"));

        let file: ConfigFile = if conf_path.exists() {
            let text = std::fs::read_to_string(&conf_path)
                .with_context(|| format!("reading config {}", conf_path.display()))?;
            toml::from_str(&text)
                .with_context(|| format!("parsing config {}", conf_path.display()))?
        } else {
            ConfigFile::default()
        };

        // Network: CLI --testnet/--network override the file.
        let network = if cli.testnet {
            Network::TestNetwork
        } else if let Some(n) = &cli.network {
            parse_network(n)?
        } else if let Some(n) = &file.network {
            parse_network(n)?
        } else {
            Network::TestNetwork
        };

        let default_wallet = file
            .default_wallet
            .clone()
            .unwrap_or_else(|| "default".to_string());

        // Wallets: from file, plus an implicit default if none declared.
        let mut wallets = BTreeMap::new();
        for (name, w) in &file.wallets {
            let dir = w.dir.clone().unwrap_or_else(|| datadir.join(name));
            wallets.insert(name.clone(), WalletEntry { name: name.clone(), dir });
        }
        wallets.entry(default_wallet.clone()).or_insert_with(|| WalletEntry {
            name: default_wallet.clone(),
            dir: datadir.join(&default_wallet),
        });

        let lwd_file = file.lightwalletd.unwrap_or(LightwalletdFile {
            server: None,
            connection: None,
            tls_roots: None,
            tls: None,
        });
        let tls_roots = match lwd_file.tls_roots {
            Some(s) => crate::lightwalletd::TlsRoots::parse(&s)?,
            None => crate::lightwalletd::TlsRoots::default(),
        };
        let force_tls = match lwd_file.tls {
            Some(s) => crate::lightwalletd::parse_tls_mode(&s)?,
            None => None,
        };
        let lightwalletd = LightwalletdConfig {
            server: cli
                .server
                .clone()
                .or(lwd_file.server)
                .unwrap_or_else(|| DEFAULT_LIGHTWALLETD.to_string()),
            connection: lwd_file.connection.unwrap_or_else(|| "direct".to_string()),
            tls_roots,
            force_tls,
        };

        let rpc_file = file.rpc.unwrap_or(RpcFile {
            bind: None,
            port: None,
            user: None,
            password: None,
            cookiefile: None,
        });
        let bind: IpAddr = cli
            .rpc_bind
            .clone()
            .or(rpc_file.bind)
            .unwrap_or_else(|| "127.0.0.1".to_string())
            .parse()
            .context("parsing rpc bind address")?;
        let rpc = RpcConfig {
            bind,
            port: cli
                .rpc_port
                .or(rpc_file.port)
                .unwrap_or_else(|| AppConfig::default_rpc_port(network)),
            user: cli.rpc_user.clone().or(rpc_file.user),
            password: cli.rpc_password.clone().or(rpc_file.password),
            cookiefile: rpc_file
                .cookiefile
                .or_else(|| Some(datadir.join(".cookie"))),
        };

        let keys_file = file.keys.unwrap_or(KeysFile {
            age_identity: None,
            auto_unlock: None,
        });
        let keys = KeysConfig {
            // Default to <datadir>/identity.txt, matching where `zecd init` writes the
            // identity, so auto-unlock works out of the box.
            age_identity: cli
                .age_identity
                .clone()
                .or(keys_file.age_identity)
                .or_else(|| Some(datadir.join("identity.txt"))),
            auto_unlock: keys_file.auto_unlock.unwrap_or(true),
        };

        let sync_file = file.sync.unwrap_or(SyncFile { interval_secs: None });
        let sync = SyncConfig {
            interval_secs: sync_file.interval_secs.unwrap_or(20),
        };

        let health_file = file.health.unwrap_or(HealthFile {
            enabled: None,
            bind: None,
            port: None,
            ready_progress: None,
        });
        let health = HealthConfig {
            enabled: health_file.enabled.unwrap_or(true),
            bind: health_file
                .bind
                .unwrap_or_else(|| "127.0.0.1".to_string())
                .parse()
                .context("parsing health bind address")?,
            port: health_file.port.unwrap_or(9233),
            ready_progress: health_file.ready_progress.unwrap_or(0.999),
        };

        let log_file = file.log.unwrap_or(LogFile { level: None, format: None });
        let log = LogConfig {
            level: log_file.level.unwrap_or_else(|| "info".to_string()),
            format: log_file.format.unwrap_or_else(|| "text".to_string()),
        };

        Ok(AppConfig {
            network,
            datadir,
            default_wallet,
            wallets,
            lightwalletd,
            rpc,
            keys,
            sync,
            health,
            log,
        })
    }
}
