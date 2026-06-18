//! Daemon configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].
//!
//! CLI flags use Bitcoin-Core-style names (`-rpcuser`, `-rpcport`, `-datadir`, `-testnet`)
//! where it helps operators, but the canonical source is the TOML config.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

use crate::network::ZNetwork;

/// Default chain upstream: a local zebrad's JSON-RPC (`zebra://127.0.0.1:8234` on mainnet,
/// `zebra://127.0.0.1:18234` on testnet/regtest - see `backend::ZEBRA_RPC_PORT_*`).
/// Deployments without a local node set `[backend] server` to their own lightwalletd
/// or a public preset (`zecrocks`).
pub const DEFAULT_SERVER: &str = "zebra";

/// Binary configuration defaults (config file, datadir, ports).
pub struct BinaryDefaults {
    /// Config file name looked up inside the datadir (`zecd.toml`).
    pub conf_file: &'static str,
    /// Default datadir when neither CLI nor env supplies one.
    pub datadir: &'static str,
    /// Environment variable consulted for the datadir.
    pub datadir_env: &'static str,
    /// Default RPC port on mainnet / test+regtest.
    pub rpc_port_main: u16,
    pub rpc_port_test: u16,
    /// Default health-probe port.
    pub health_port: u16,
}

pub const ZECD_DEFAULTS: BinaryDefaults = BinaryDefaults {
    conf_file: "zecd.toml",
    datadir: "./zecd-data",
    datadir_env: "ZECD_DATADIR",
    rpc_port_main: 8232,
    rpc_port_test: 18232,
    health_port: 9233,
};

/// Resolve the ordered list of upstream server tokens by precedence:
/// CLI `--server` > file `servers` array > file `server` string > built-in default
/// (a local zebrad).
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
        vec![DEFAULT_SERVER.to_string()]
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub network: ZNetwork,
    pub datadir: PathBuf,
    pub default_wallet: String,
    pub wallets: BTreeMap<String, WalletEntry>,
    pub backend: BackendConfig,
    pub zebra: ZebraConfig,
    pub rpc: RpcConfig,
    pub keys: KeysConfig,
    pub keystore: KeystoreConfig,
    pub sync: SyncConfig,
    pub spend: SpendConfig,
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
    pub dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// Ordered list of server tokens; each is `zebra` (a local zebrad, the default) |
    /// `zebra://host:port` | `ecc` | `ywallet` | `zecrocks` or a `host:port` (or a
    /// comma-separated `host:port` list). Tried in order, always preferring the first.
    pub servers: Vec<String>,
    /// Optional SOCKS5 proxy to route every backend connection through, parsed from the
    /// `connection` setting (`direct` | `tor` | `socks5://host:port`). `None` = direct.
    pub proxy: Option<SocketAddr>,
    /// TLS root certificates to trust (`native` or `webpki`).
    pub tls_roots: crate::backend::TlsRoots,
    /// Force TLS on/off; `None` = auto (TLS for remote hosts, plaintext for localhost).
    pub force_tls: Option<bool>,
    /// Per-attempt dial timeout (seconds) for connecting to a backend endpoint.
    pub connect_timeout_secs: u64,
    /// Reconnect backoff base delay (seconds).
    pub reconnect_base_secs: u64,
    /// Reconnect backoff maximum delay (seconds).
    pub reconnect_max_secs: u64,
    /// While running on a fallback, how often (seconds) to re-probe higher-priority servers.
    pub primary_recheck_secs: u64,
}

/// `[zebra]` - credentials for `zebra://host:port` endpoints in the `[backend]`
/// server list (direct-to-zebrad mode). All `zebra://` endpoints share these; a cookie
/// file wins over user/password, and nothing set means no auth (zebrad with
/// `enable_cookie_auth = false`).
#[derive(Debug, Clone, Default)]
pub struct ZebraConfig {
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_cookie: Option<PathBuf>,
}

impl ZebraConfig {
    pub fn auth(&self) -> crate::chain::zebra::ZebraAuth {
        crate::chain::zebra::ZebraAuth {
            user: self.rpc_user.clone(),
            password: self.rpc_password.clone(),
            cookie: self.rpc_cookie.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcConfig {
    pub bind: IpAddr,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    /// Bitcoin-Core-style `rpcauth` entries (`<user>:<salt>$<hmac-sha256 hex>`), each an
    /// additional accepted credential; generate them with bitcoind's `rpcauth.py`.
    pub auth: Vec<String>,
    /// Path to a bitcoind-style cookie file; generated at startup when no user/password set.
    pub cookiefile: Option<PathBuf>,
    /// Max concurrent in-flight requests before returning HTTP 503 (Bitcoin Core's
    /// `-rpcworkqueue`, default 100).
    pub work_queue: usize,
    /// RPC method safelist. Empty (the default) serves every method; non-empty serves *only*
    /// these methods, with anything else rejected as method-not-found (`-32601`). Names are
    /// validated at startup against [`crate::rpc::ALL_METHODS`], so a typo fails fast.
    pub allowed_methods: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KeysConfig {
    /// age identity file used to decrypt the wallet seed for unattended sending.
    pub age_identity: Option<PathBuf>,
    /// When true, decrypt the seed at startup so sends need no `walletpassphrase`.
    pub auto_unlock: bool,
}

/// `[keystore]` - a cloud KMS key that wraps the wallet's at-rest encryption key
/// ("envelope encryption" / auto-unseal). `provider` + `key` are required to *create* a
/// KMS wallet (`init --keystore`, `rewrap`); a daemon unlocking an existing KMS wallet
/// reads provider/key from the wallet's own `keys.toml` and uses only `endpoint` from here.
#[derive(Debug, Clone, Default)]
pub struct KeystoreConfig {
    pub provider: Option<crate::keystore::KeystoreProvider>,
    /// AWS key ARN/id/alias, or GCP cryptoKey resource name.
    pub key: Option<String>,
    /// API endpoint override (emulators, VPC/private endpoints).
    pub endpoint: Option<String>,
}

impl KeystoreConfig {
    /// The configured keystore, required (for `init --keystore` / `rewrap`).
    pub fn required(&self) -> anyhow::Result<crate::keystore::Keystore> {
        match (self.provider, &self.key) {
            (Some(provider), Some(key)) => Ok(crate::keystore::Keystore {
                provider,
                key: key.clone(),
                endpoint: self.endpoint.clone(),
            }),
            _ => Err(anyhow::anyhow!(
                "no cloud keystore configured: set [keystore] provider (\"aws-kms\" or \
                 \"gcp-kms\") and key in the config file"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub interval_secs: u64,
    /// How often (at most) to re-broadcast wallet txs that are unmined and unexpired.
    pub rebroadcast_secs: u64,
}

/// `[spend]` - the wallet-wide confirmations policy (ZIP 315 defaults, like Zallet's
/// `trusted_confirmations`/`untrusted_confirmations`): how deep an output must be before
/// the wallet treats it as spendable, which also anchors `getbalance`/`getbalances`/
/// `getwalletinfo` and the sync engine's spend proposals.
#[derive(Debug, Clone)]
pub struct SpendConfig {
    /// Confirmations before the wallet's *own* outputs (change) are spendable. Default 3.
    pub trusted_confirmations: u32,
    /// Confirmations before third-party outputs are spendable. Must be at least
    /// `trusted_confirmations`. Default 10.
    pub untrusted_confirmations: u32,
    /// What sends are allowed to reveal on-chain. Default `AllowRevealedRecipients`.
    pub privacy: SendPrivacy,
}

impl Default for SpendConfig {
    fn default() -> Self {
        Self {
            trusted_confirmations: 3,
            untrusted_confirmations: 10,
            privacy: SendPrivacy::AllowRevealedRecipients,
        }
    }
}

/// `[spend] privacy_policy` - Zallet/zcashd's privacy-policy idea reduced to what matters
/// for an Orchard-only wallet: whether a send may leave the Orchard pool. Crossing pools
/// reveals the transferred amount on-chain (and, for transparent recipients, the recipient
/// too); zcashd and Zallet require an explicit `AllowRevealed*` opt-in for that, and this
/// knob is zecd's equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPrivacy {
    /// Every recipient must be able to receive in the Orchard pool, so a send never reveals
    /// amounts or recipients.
    FullPrivacy,
    /// Recipients without an Orchard receiver (transparent and Sapling-only addresses) are
    /// allowed; such sends reveal the amount (and a transparent recipient) on-chain. This is
    /// the default: the Bitcoin-RPC dialect promises "send to any valid address".
    AllowRevealedRecipients,
}

impl SendPrivacy {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "FullPrivacy" => Ok(Self::FullPrivacy),
            "AllowRevealedRecipients" => Ok(Self::AllowRevealedRecipients),
            other => anyhow::bail!(
                "[spend] privacy_policy must be \"FullPrivacy\" or \"AllowRevealedRecipients\" \
                 (got \"{other}\")"
            ),
        }
    }
}

impl SpendConfig {
    /// Build the [`ConfirmationsPolicy`] this configuration describes. Values are clamped
    /// to at least 1 (a shielded note is never spendable unmined); trusted exceeding
    /// untrusted is a configuration error, as in librustzcash.
    pub fn confirmations_policy(&self) -> anyhow::Result<ConfirmationsPolicy> {
        let trusted = NonZeroU32::new(self.trusted_confirmations.max(1)).expect("clamped");
        let untrusted = NonZeroU32::new(self.untrusted_confirmations.max(1)).expect("clamped");
        // The third argument exists because this crate enables `transparent-inputs` (so
        // transparent receivers surface in getrawtransaction/getaddressinfo): it allows
        // 0-conf spends of transparent UTXOs, matching the ZIP-315 default policy. It is
        // inert for zecd, whose wallets never expose transparent receivers.
        ConfirmationsPolicy::new(trusted, untrusted, true).map_err(|_| {
            anyhow::anyhow!(
                "[spend] trusted_confirmations ({}) must not exceed untrusted_confirmations ({})",
                self.trusted_confirmations,
                self.untrusted_confirmations
            )
        })
    }
}

impl AppConfig {
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
    backend: Option<BackendFile>,
    zebra: Option<ZebraFile>,
    rpc: Option<RpcFile>,
    keys: Option<KeysFile>,
    keystore: Option<KeystoreFile>,
    sync: Option<SyncFile>,
    spend: Option<SpendFile>,
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
struct BackendFile {
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZebraFile {
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    rpc_cookie: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcFile {
    bind: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    auth: Option<Vec<String>>,
    cookiefile: Option<PathBuf>,
    work_queue: Option<usize>,
    allowed_methods: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    age_identity: Option<PathBuf>,
    auto_unlock: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeystoreFile {
    provider: Option<String>,
    key: Option<String>,
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncFile {
    interval_secs: Option<u64>,
    rebroadcast_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendFile {
    trusted_confirmations: Option<u32>,
    untrusted_confirmations: Option<u32>,
    privacy_policy: Option<String>,
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

    /// Use regtest - a local zebra regtest chain (overrides config `network`).
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

    /// rpcauth credential (`<user>:<salt>$<hmac-sha256 hex>`); may be repeated.
    #[arg(long = "rpcauth", value_name = "USER:SALT$HASH")]
    pub rpc_auth: Vec<String>,

    /// Chain upstream: zebra (local zebrad, default) | zebra://host:port | ecc | ywallet |
    /// zecrocks | host:port[,host:port] (lightwalletd).
    #[arg(long, value_name = "SERVER")]
    pub server: Option<String>,

    /// How to reach the backend: direct | tor | socks5://host:port (routes all traffic through
    /// the SOCKS5 proxy).
    #[arg(long, value_name = "MODE")]
    pub connection: Option<String>,

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
    /// Re-wrap an existing wallet's mnemonic under the configured [keystore] cloud KMS key
    /// (migrate at-rest custody onto AWS/GCP KMS, or rotate to a new KMS key), then exit.
    Rewrap(RewrapArgs),
    /// Print a wallet's Unified Full Viewing Key (for pairing a watch-only instance via
    /// `init --ufvk`), then exit.
    ExportUfvk(ExportUfvkArgs),
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

    /// Passphrase-encrypt the wallet (Bitcoin-Core style): the mnemonic is wrapped with a
    /// passphrase instead of the age identity, and the wallet starts locked - sending requires
    /// `walletpassphrase`. The passphrase is read from `ZECD_WALLET_PASSPHRASE` or stdin.
    #[arg(long)]
    pub encrypt: bool,

    /// Wrap the wallet's at-rest encryption key with the cloud KMS key configured under
    /// [keystore] (AWS KMS or Google Cloud KMS). The wallet auto-unlocks at startup via one
    /// IAM-gated KMS Decrypt - no identity file, no passphrase.
    #[arg(long, conflicts_with = "encrypt")]
    pub keystore: bool,

    /// Create a watch-only wallet from this Unified Full Viewing Key instead of a mnemonic
    /// (export it from the spending wallet with `export-ufvk`). The wallet sees balances,
    /// history, and addresses, but holds no spending material - spend and encryption RPCs
    /// are disabled. A watch-only wallet has no key to wrap, so this excludes `--keystore`.
    #[arg(long, value_name = "UFVK", conflicts_with_all = ["restore", "encrypt", "keystore"])]
    pub ufvk: Option<String>,

    /// Optional birthday height; defaults to the current chain tip for new wallets.
    #[arg(long)]
    pub birthday: Option<u32>,
}

#[derive(Debug, clap::Args)]
pub struct RewrapArgs {
    /// Wallet name (selects <datadir>/<name>).
    #[arg(long, default_value = "default")]
    pub wallet: String,
}

#[derive(Debug, clap::Args)]
pub struct ExportUfvkArgs {
    /// Wallet name (selects <datadir>/<name>).
    #[arg(long, default_value = "default")]
    pub wallet: String,
}

impl AppConfig {
    /// Resolve the effective configuration from CLI flags and the TOML file, using zecd's
    /// file/port defaults.
    pub fn resolve(cli: &Cli) -> anyhow::Result<AppConfig> {
        Self::resolve_with(cli, &ZECD_DEFAULTS)
    }

    /// Resolve the effective configuration with the binary's defaults (`zecd`).
    pub fn resolve_with(cli: &Cli, defaults: &BinaryDefaults) -> anyhow::Result<AppConfig> {
        // Datadir precedence: CLI > env (ZECD_DATADIR) > config file > default.
        // The config file is located *before* its own `datadir` can apply (like bitcoind:
        // `-conf` resolution never depends on a datadir set inside the file), so the file
        // lookup uses only CLI/env.
        let cli_datadir = cli
            .datadir
            .clone()
            .or_else(|| std::env::var_os(defaults.datadir_env).map(PathBuf::from));

        let conf_path = cli.conf.clone().unwrap_or_else(|| {
            cli_datadir
                .clone()
                .unwrap_or_else(|| PathBuf::from(defaults.datadir))
                .join(defaults.conf_file)
        });

        let file: ConfigFile = if conf_path.exists() {
            let text = std::fs::read_to_string(&conf_path)
                .with_context(|| format!("reading config {}", conf_path.display()))?;
            toml::from_str(&text)
                .with_context(|| format!("parsing config {}", conf_path.display()))?
        } else {
            ConfigFile::default()
        };

        let datadir = cli_datadir
            .or_else(|| file.datadir.clone())
            .unwrap_or_else(|| PathBuf::from(defaults.datadir));

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
            wallets.insert(name.clone(), WalletEntry { dir });
        }
        wallets
            .entry(default_wallet.clone())
            .or_insert_with(|| WalletEntry {
                dir: datadir.join(&default_wallet),
            });

        let backend_file = file.backend.unwrap_or(BackendFile {
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
        let tls_roots = match backend_file.tls_roots {
            Some(s) => crate::backend::TlsRoots::parse(&s)?,
            None => crate::backend::TlsRoots::default(),
        };
        let force_tls = match backend_file.tls {
            Some(s) => crate::backend::parse_tls_mode(&s)?,
            None => None,
        };
        let servers = select_server_tokens(
            cli.server.clone(),
            backend_file.servers,
            backend_file.server,
        );
        // CLI `--connection` wins over the file `connection`; both parse to an optional SOCKS5
        // proxy. Validated here so a typo fails at startup, before any wallet/network I/O.
        let connection = cli
            .connection
            .clone()
            .or(backend_file.connection)
            .unwrap_or_else(|| "direct".to_string());
        let proxy = crate::backend::parse_connection_mode(&connection)?;
        let reconnect_base_secs = backend_file.reconnect_base_secs.unwrap_or(1).max(1);
        let backend = BackendConfig {
            servers,
            proxy,
            tls_roots,
            force_tls,
            connect_timeout_secs: backend_file.connect_timeout_secs.unwrap_or(10).max(1),
            reconnect_base_secs,
            reconnect_max_secs: backend_file
                .reconnect_max_secs
                .unwrap_or(60)
                .max(reconnect_base_secs),
            primary_recheck_secs: backend_file.primary_recheck_secs.unwrap_or(60).max(1),
        };

        let zebra_file = file.zebra.unwrap_or_default();
        let zebra = ZebraConfig {
            rpc_user: zebra_file.rpc_user,
            rpc_password: zebra_file.rpc_password,
            rpc_cookie: zebra_file.rpc_cookie,
        };

        let rpc_file = file.rpc.unwrap_or(RpcFile {
            bind: None,
            port: None,
            user: None,
            password: None,
            auth: None,
            cookiefile: None,
            work_queue: None,
            allowed_methods: None,
        });
        // RPC method safelist: validate every entry against the known method set so a typo
        // fails at startup rather than silently disabling a method the operator meant to keep
        // (or, worse, appearing to allow one it doesn't). An absent or empty list means "no
        // restriction" - never "deny everything", which would be a useless footgun.
        let allowed_methods = rpc_file.allowed_methods.unwrap_or_default();
        for m in &allowed_methods {
            if !crate::rpc::is_known_method(m) {
                anyhow::bail!(
                    "[rpc] allowed_methods contains unknown method {m:?}; \
                     it is not an RPC method this build implements (see the example config \
                     for the full list)"
                );
            }
        }
        let bind: IpAddr = cli
            .rpc_bind
            .clone()
            .or(rpc_file.bind)
            .unwrap_or_else(|| "127.0.0.1".to_string())
            .parse()
            .context("parsing rpc bind address")?;
        let rpc = RpcConfig {
            bind,
            port: cli.rpc_port.or(rpc_file.port).unwrap_or(match network {
                ZNetwork::Main => defaults.rpc_port_main,
                ZNetwork::Test | ZNetwork::Regtest(_) => defaults.rpc_port_test,
            }),
            user: cli.rpc_user.clone().or(rpc_file.user),
            password: cli.rpc_password.clone().or(rpc_file.password),
            // rpcauth entries accumulate across CLI and file, matching bitcoind where
            // every -rpcauth/conf line is an accepted credential.
            auth: cli
                .rpc_auth
                .iter()
                .cloned()
                .chain(rpc_file.auth.unwrap_or_default())
                .collect(),
            cookiefile: rpc_file
                .cookiefile
                .or_else(|| Some(datadir.join(".cookie"))),
            work_queue: rpc_file.work_queue.unwrap_or(100).max(1),
            allowed_methods,
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

        let keystore_file = file.keystore.unwrap_or_default();
        let keystore = KeystoreConfig {
            provider: keystore_file
                .provider
                .as_deref()
                .map(crate::keystore::KeystoreProvider::parse)
                .transpose()
                .context("parsing [keystore] provider")?,
            key: keystore_file.key,
            endpoint: keystore_file.endpoint,
        };
        // Half-configured keystores fail at startup, not at the first init/rewrap/unlock.
        if keystore.provider.is_some() && keystore.key.is_none() {
            anyhow::bail!("[keystore] provider is set but key is missing");
        }
        if keystore.provider.is_none() && keystore.key.is_some() {
            anyhow::bail!("[keystore] key is set but provider is missing");
        }

        let sync_file = file.sync.unwrap_or(SyncFile {
            interval_secs: None,
            rebroadcast_secs: None,
        });
        let sync = SyncConfig {
            interval_secs: sync_file.interval_secs.unwrap_or(20),
            rebroadcast_secs: sync_file.rebroadcast_secs.unwrap_or(60).max(1),
        };

        let spend_file = file.spend.unwrap_or_default();
        let spend = SpendConfig {
            trusted_confirmations: spend_file.trusted_confirmations.unwrap_or(3),
            untrusted_confirmations: spend_file.untrusted_confirmations.unwrap_or(10),
            privacy: spend_file
                .privacy_policy
                .as_deref()
                .map(SendPrivacy::parse)
                .transpose()?
                .unwrap_or(SendPrivacy::AllowRevealedRecipients),
        };
        // Fail at startup, not on the first balance/send call.
        spend.confirmations_policy()?;

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
            port: health_file.port.unwrap_or(defaults.health_port),
            ready_progress: health_file.ready_progress.unwrap_or(0.999),
        };

        let log_file = file.log.unwrap_or(LogFile {
            level: None,
            format: None,
        });
        let log = LogConfig {
            level: log_file.level.unwrap_or_else(|| "info".to_string()),
            format: log_file.format.unwrap_or_else(|| "text".to_string()),
        };

        Ok(AppConfig {
            network,
            datadir,
            default_wallet,
            wallets,
            backend,
            zebra,
            rpc,
            keys,
            keystore,
            sync,
            spend,
            health,
            log,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_section_builds_policy_and_validates() {
        // Parses from TOML; explicit values land in the policy.
        let f: SpendFile =
            toml::from_str("trusted_confirmations = 1\nuntrusted_confirmations = 2").unwrap();
        let s = SpendConfig {
            trusted_confirmations: f.trusted_confirmations.unwrap_or(3),
            untrusted_confirmations: f.untrusted_confirmations.unwrap_or(10),
            ..Default::default()
        };
        let p = s.confirmations_policy().unwrap();
        assert_eq!((p.trusted().get(), p.untrusted().get()), (1, 2));
        // The defaults are ZIP 315's 3/10.
        let p = SpendConfig {
            trusted_confirmations: 3,
            untrusted_confirmations: 10,
            ..Default::default()
        }
        .confirmations_policy()
        .unwrap();
        assert_eq!((p.trusted().get(), p.untrusted().get()), (3, 10));
        // 0 clamps to 1 (a shielded note is never spendable unmined).
        let p = SpendConfig {
            trusted_confirmations: 0,
            untrusted_confirmations: 1,
            ..Default::default()
        }
        .confirmations_policy()
        .unwrap();
        assert_eq!((p.trusted().get(), p.untrusted().get()), (1, 1));
        // trusted > untrusted is rejected (surfaces as a startup error).
        assert!(SpendConfig {
            trusted_confirmations: 11,
            untrusted_confirmations: 10,
            ..Default::default()
        }
        .confirmations_policy()
        .is_err());
        // Unknown keys in the section are rejected like everywhere else.
        assert!(toml::from_str::<SpendFile>("min_conf = 1").is_err());
    }

    #[test]
    fn keystore_section_parses_and_validates() {
        let f: KeystoreFile = toml::from_str(
            "provider = \"aws-kms\"\nkey = \"arn:aws:kms:us-east-1:1:key/k\"\nendpoint = \"http://localhost:4566\"",
        )
        .unwrap();
        assert_eq!(f.provider.as_deref(), Some("aws-kms"));
        // Unknown keys in the section are rejected like everywhere else.
        assert!(toml::from_str::<KeystoreFile>("region = \"us-east-1\"").is_err());

        // `required()` needs both provider and key (init --keystore / rewrap).
        let cfg = KeystoreConfig {
            provider: Some(crate::keystore::KeystoreProvider::GcpKms),
            key: Some("projects/p/locations/l/keyRings/r/cryptoKeys/k".to_string()),
            endpoint: None,
        };
        assert_eq!(cfg.required().unwrap().key, cfg.key.clone().unwrap());
        assert!(KeystoreConfig::default().required().is_err());
    }

    #[test]
    fn privacy_policy_parses_known_values_only() {
        assert_eq!(
            SendPrivacy::parse("FullPrivacy").unwrap(),
            SendPrivacy::FullPrivacy
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedRecipients").unwrap(),
            SendPrivacy::AllowRevealedRecipients
        );
        // Unknown values (including other zcashd policies that don't apply to an
        // Orchard-only wallet) are a startup error, never a silent default.
        assert!(SendPrivacy::parse("NoPrivacy").is_err());
        assert!(SendPrivacy::parse("fullprivacy").is_err());
    }

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
        // Nothing configured -> built-in default (a local zebrad).
        assert_eq!(
            select_server_tokens(None, None, None),
            vec![DEFAULT_SERVER.to_string()]
        );
    }

    #[test]
    fn backend_file_parses_array_and_backoff() {
        let f: BackendFile = toml::from_str(
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
    fn backend_file_rejects_unknown_field() {
        // `deny_unknown_fields` must still reject typos/unsupported keys.
        assert!(toml::from_str::<BackendFile>("bogus_key = 1").is_err());
    }

    #[test]
    fn zebra_section_parses_and_validates() {
        let f: ConfigFile = toml::from_str(
            "[zebra]\nrpc_user = \"u\"\nrpc_password = \"p\"\nrpc_cookie = \"/tmp/.cookie\"\n",
        )
        .unwrap();
        let z = f.zebra.unwrap();
        assert_eq!(z.rpc_user.as_deref(), Some("u"));
        assert_eq!(z.rpc_password.as_deref(), Some("p"));
        assert_eq!(z.rpc_cookie, Some(PathBuf::from("/tmp/.cookie")));
        // The section maps onto the zebra backend's auth type.
        let auth = ZebraConfig {
            rpc_user: z.rpc_user,
            rpc_password: z.rpc_password,
            rpc_cookie: z.rpc_cookie,
        }
        .auth();
        assert_eq!(auth.user.as_deref(), Some("u"));
        assert!(auth.cookie.is_some());
        // Typos are rejected like every other section.
        assert!(toml::from_str::<ZebraFile>("user = \"u\"").is_err());
        // An absent section resolves to no credentials.
        assert!(ZebraConfig::default().auth().header().unwrap().is_none());
    }

    #[test]
    fn file_datadir_is_honored_and_cli_wins() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(&conf, "datadir = \"/tmp/zecd-from-file\"\n").unwrap();

        // A `datadir` set in the config file governs data placement...
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.datadir, PathBuf::from("/tmp/zecd-from-file"));

        // ...but --datadir on the CLI still wins over the file.
        let cli = Cli::parse_from([
            "zecd",
            "--conf",
            conf.to_str().unwrap(),
            "--datadir",
            "/tmp/zecd-from-cli",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.datadir, PathBuf::from("/tmp/zecd-from-cli"));
    }

    #[test]
    fn connection_mode_resolves_to_proxy_and_rejects_garbage() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        // An unrecognized connection mode must fail at startup, never silently fall back to
        // direct connections (that would defeat the privacy property the operator configured).
        std::fs::write(&conf, "[backend]\nconnection = \"torr\"\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let err = AppConfig::resolve(&cli).unwrap_err().to_string();
        assert!(err.contains("invalid connection"), "got: {err}");

        // "tor" resolves to Tor's conventional local SOCKS port…
        std::fs::write(&conf, "[backend]\nconnection = \"tor\"\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.backend.proxy, Some("127.0.0.1:9050".parse().unwrap()));

        // …"direct" to no proxy, and the CLI --connection flag wins over the file.
        let cli = Cli::parse_from([
            "zecd",
            "--conf",
            conf.to_str().unwrap(),
            "--connection",
            "direct",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.backend.proxy, None);
    }

    #[test]
    fn rpc_allowed_methods_parses_and_validates() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        // Absent -> empty list (no restriction; every method served).
        std::fs::write(&conf, "network = \"test\"\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(cfg.rpc.allowed_methods.is_empty());

        // A valid list is preserved verbatim.
        std::fs::write(
            &conf,
            "[rpc]\nallowed_methods = [\"getbalance\", \"getnewaddress\", \"sendtoaddress\"]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.rpc.allowed_methods,
            vec![
                "getbalance".to_string(),
                "getnewaddress".to_string(),
                "sendtoaddress".to_string()
            ]
        );

        // An explicit empty array is "no restriction", never "deny everything".
        std::fs::write(&conf, "[rpc]\nallowed_methods = []\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(cfg.rpc.allowed_methods.is_empty());

        // An unknown method name is a startup error (typo protection), naming the offender.
        std::fs::write(
            &conf,
            "[rpc]\nallowed_methods = [\"getbalance\", \"getblance\"]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let err = AppConfig::resolve(&cli).unwrap_err().to_string();
        assert!(err.contains("getblance"), "got: {err}");
    }

    #[test]
    fn shipped_configs_parse() {
        // The example and docker configs must deserialize (deny_unknown_fields catches typos and
        // drift as the schema evolves).
        toml::from_str::<ConfigFile>(include_str!("../zecd.example.toml"))
            .expect("zecd.example.toml");
        toml::from_str::<ConfigFile>(include_str!("../deploy/zecd.toml"))
            .expect("deploy/zecd.toml");
        toml::from_str::<ConfigFile>(include_str!("../deploy/zecd.mainnet.toml"))
            .expect("deploy/zecd.mainnet.toml");
    }
}
