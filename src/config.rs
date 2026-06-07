//! Daemon configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].
//!
//! CLI flags use Bitcoin-Core-style names (`-rpcuser`, `-rpcport`, `-datadir`, `-testnet`)
//! where it helps operators, but the canonical source is the TOML config.
#![allow(dead_code)] // some config fields/helpers are part of the model but not yet read

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;

use crate::network::ZNetwork;

/// Default lightwalletd endpoint: the public zecrocks infrastructure
/// (`zec.rocks:443` on mainnet, `testnet.zec.rocks:443` on testnet). Self-hosted
/// deployments override `[lightwalletd] server` with their local node.
pub const DEFAULT_LIGHTWALLETD: &str = "zecrocks";

/// Resolve the ordered list of lightwalletd server tokens by precedence:
/// CLI `--server` > file `servers` array > file `server` string > built-in default.
fn select_server_tokens(
    cli_server: Option<String>,
    file_servers: Option<Vec<String>>,
    file_server: Option<String>,
) -> Vec<String> {
    if let Some(s) = cli_server {
        vec![s]
    } else if let Some(list) = file_servers.filter(|l| !l.is_empty()) {
        list
    } else if let Some(s) = file_server {
        vec![s]
    } else {
        vec![DEFAULT_LIGHTWALLETD.to_string()]
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub network: ZNetwork,
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
    /// Ordered list of server tokens; each is `ecc` | `ywallet` | `zecrocks` or a `host:port`
    /// (or a comma-separated `host:port` list). Tried in order, always preferring the first.
    pub servers: Vec<String>,
    /// `direct` | `tor` | `socks5://host:port`.
    pub connection: String,
    /// TLS root certificates to trust (`native` or `webpki`).
    pub tls_roots: crate::lightwalletd::TlsRoots,
    /// Force TLS on/off; `None` = auto (TLS for remote hosts, plaintext for localhost).
    pub force_tls: Option<bool>,
    /// Per-attempt dial timeout (seconds) for connecting to a lightwalletd endpoint.
    pub connect_timeout_secs: u64,
    /// Reconnect backoff base delay (seconds).
    pub reconnect_base_secs: u64,
    /// Reconnect backoff maximum delay (seconds).
    pub reconnect_max_secs: u64,
    /// While running on a fallback, how often (seconds) to re-probe higher-priority servers.
    pub primary_recheck_secs: u64,
}

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Path to a bitcoind-style cookie file; generated at startup when no user/password set.
    pub cookiefile: Option<PathBuf>,
    /// Max concurrent in-flight requests before returning HTTP 503 (Bitcoin Core's
    /// `-rpcworkqueue`, default 100).
    pub work_queue: usize,
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
    pub fn default_rpc_port(network: ZNetwork) -> u16 {
        match network {
            ZNetwork::Main => 8232,
            ZNetwork::Test | ZNetwork::Regtest(_) => 18232,
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
    servers: Option<Vec<String>>,
    connection: Option<String>,
    tls_roots: Option<String>,
    tls: Option<String>,
    connect_timeout_secs: Option<u64>,
    reconnect_base_secs: Option<u64>,
    reconnect_max_secs: Option<u64>,
    primary_recheck_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcFile {
    bind: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    cookiefile: Option<PathBuf>,
    work_queue: Option<usize>,
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

    /// Use regtest - a local zebra+lightwalletd chain (overrides config `network`).
    #[arg(long)]
    pub regtest: bool,

    /// Network: "main", "test", or "regtest".
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

        // Network: CLI --regtest/--testnet/--network override the file.
        let network = if cli.regtest {
            crate::network::regtest()
        } else if cli.testnet {
            ZNetwork::Test
        } else if let Some(n) = &cli.network {
            ZNetwork::parse(n)?
        } else if let Some(n) = &file.network {
            ZNetwork::parse(n)?
        } else {
            ZNetwork::Test
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
            servers: None,
            connection: None,
            tls_roots: None,
            tls: None,
            connect_timeout_secs: None,
            reconnect_base_secs: None,
            reconnect_max_secs: None,
            primary_recheck_secs: None,
        });
        let tls_roots = match lwd_file.tls_roots {
            Some(s) => crate::lightwalletd::TlsRoots::parse(&s)?,
            None => crate::lightwalletd::TlsRoots::default(),
        };
        let force_tls = match lwd_file.tls {
            Some(s) => crate::lightwalletd::parse_tls_mode(&s)?,
            None => None,
        };
        let servers = select_server_tokens(cli.server.clone(), lwd_file.servers, lwd_file.server);
        let reconnect_base_secs = lwd_file.reconnect_base_secs.unwrap_or(1).max(1);
        let lightwalletd = LightwalletdConfig {
            servers,
            connection: lwd_file.connection.unwrap_or_else(|| "direct".to_string()),
            tls_roots,
            force_tls,
            connect_timeout_secs: lwd_file.connect_timeout_secs.unwrap_or(10).max(1),
            reconnect_base_secs,
            reconnect_max_secs: lwd_file.reconnect_max_secs.unwrap_or(60).max(reconnect_base_secs),
            primary_recheck_secs: lwd_file.primary_recheck_secs.unwrap_or(60).max(1),
        };

        let rpc_file = file.rpc.unwrap_or(RpcFile {
            bind: None,
            port: None,
            user: None,
            password: None,
            cookiefile: None,
            work_queue: None,
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
            work_queue: rpc_file.work_queue.unwrap_or(100).max(1),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_token_precedence() {
        // CLI wins over everything.
        assert_eq!(
            select_server_tokens(
                Some("cli:1".into()),
                Some(vec!["arr:1".into()]),
                Some("str:1".into())
            ),
            vec!["cli:1".to_string()]
        );
        // The `servers` array beats the legacy `server` string.
        assert_eq!(
            select_server_tokens(
                None,
                Some(vec!["a:1".into(), "b:2".into()]),
                Some("str:1".into())
            ),
            vec!["a:1".to_string(), "b:2".to_string()]
        );
        // An empty array falls through to the string.
        assert_eq!(
            select_server_tokens(None, Some(vec![]), Some("str:1".into())),
            vec!["str:1".to_string()]
        );
        // Nothing configured -> built-in default.
        assert_eq!(
            select_server_tokens(None, None, None),
            vec![DEFAULT_LIGHTWALLETD.to_string()]
        );
    }

    #[test]
    fn lightwalletd_file_parses_array_and_backoff() {
        let f: LightwalletdFile = toml::from_str(
            r#"
            servers = ["127.0.0.1:9067", "zec.rocks:443"]
            connect_timeout_secs = 5
            reconnect_base_secs = 2
            reconnect_max_secs = 30
            primary_recheck_secs = 90
            "#,
        )
        .unwrap();
        assert_eq!(f.servers.unwrap().len(), 2);
        assert_eq!(f.connect_timeout_secs, Some(5));
        assert_eq!(f.reconnect_base_secs, Some(2));
        assert_eq!(f.reconnect_max_secs, Some(30));
        assert_eq!(f.primary_recheck_secs, Some(90));
    }

    #[test]
    fn lightwalletd_file_rejects_unknown_field() {
        // `deny_unknown_fields` must still reject typos/unsupported keys.
        assert!(toml::from_str::<LightwalletdFile>("bogus_key = 1").is_err());
    }

    #[test]
    fn shipped_configs_parse() {
        // The example and docker configs must deserialize (deny_unknown_fields catches typos and
        // drift as the schema evolves).
        toml::from_str::<ConfigFile>(include_str!("../zecd.example.toml")).expect("zecd.example.toml");
        toml::from_str::<ConfigFile>(include_str!("../deploy/zecd.toml")).expect("deploy/zecd.toml");
    }
}
