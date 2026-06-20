//! Daemon configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].
//!
//! CLI flags use Bitcoin-Core-style names (`-rpcuser`, `-rpcport`, `-datadir`, `-testnet`)
//! where it helps operators, but the canonical source is the TOML config.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

use crate::network::ZNetwork;
use crate::pools::{Pool, PoolSet};

/// Default chain upstream: a local zebrad's JSON-RPC (`zebra://127.0.0.1:8234` on mainnet,
/// `zebra://127.0.0.1:18234` on testnet/regtest - see `backend::ZEBRA_RPC_PORT_*`). A zebrad
/// on another host/port is set via `[backend] server = "zebra://host:port"`.
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

/// Resolve the upstream `server` token by precedence: CLI `--server` > file `server` >
/// built-in default (a local zebrad).
fn select_server_token(cli_server: Option<String>, file_server: Option<String>) -> String {
    cli_server
        .or(file_server)
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

/// Read a single secret (e.g. the RPC password) from a file, trimming a trailing newline/CR
/// (the common `echo "secret" > file` gotcha) but preserving any other surrounding whitespace.
/// Used for `[rpc] password_file` so the secret can live in a mounted Secret, not the TOML.
fn read_secret_file(path: &std::path::Path) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading secret file {}", path.display()))?;
    Ok(raw.trim_end_matches(['\n', '\r']).to_string())
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
    pub sync: SyncConfig,
    pub spend: SpendConfig,
    /// Global default enabled pools / UA receivers, applied to wallets that don't override them
    /// (including the implicit default wallet that has no `[wallets.<name>]` entry).
    pub pools: PoolsConfig,
    pub health: HealthConfig,
    pub log: LogConfig,
}

/// `[pools]` - the wallet's shielded pool configuration: which pools are enabled and which
/// receivers the Unified Addresses it hands out include by default. A default receiver may never
/// name a pool that isn't enabled (validated at startup). Per-wallet `[wallets.<name>]` entries
/// can override either field; this is the global default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolsConfig {
    /// Shielded pools the wallet receives into and spends from.
    pub enabled: PoolSet,
    /// Receivers included in the UAs handed out by `getnewaddress` when no per-call override is
    /// given. Always a subset of `enabled`.
    pub default_receivers: PoolSet,
}

impl Default for PoolsConfig {
    fn default() -> Self {
        // Preserves zecd's historical behaviour: Orchard-only receiving.
        Self {
            enabled: PoolSet::single(Pool::Orchard),
            default_receivers: PoolSet::single(Pool::Orchard),
        }
    }
}

/// What `/readyz` means - chosen to fit a deployment's priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessMode {
    /// Ready only once the wallet has actually scanned to (near) the chain tip: connected and
    /// within `max_scan_lag` blocks of the tip. Strict - a from-birthday restore stays "not
    /// ready" until it catches up. Use when a client must not see stale balances/history.
    Synced,
    /// Ready as soon as the backend is connected and its chain tip is past the wallet's birthday
    /// (a cheap sanity check that we're talking to the right, live network). Does NOT wait for
    /// the wallet to finish scanning, so RPC clients can reach zecd while it catches up - at the
    /// cost of reads possibly lagging the tip. Avoids readiness flapping during long scans.
    Connected,
}

impl ReadinessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReadinessMode::Synced => "synced",
            ReadinessMode::Connected => "connected",
        }
    }

    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "synced" => Ok(ReadinessMode::Synced),
            "connected" => Ok(ReadinessMode::Connected),
            other => Err(anyhow::anyhow!(
                "invalid [health] readiness {other:?}: expected \"synced\" or \"connected\""
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Serve liveness/readiness probes on a separate, unauthenticated HTTP port.
    pub enabled: bool,
    pub bind: IpAddr,
    pub port: u16,
    /// What `/readyz` gates on (see [`ReadinessMode`]).
    pub readiness: ReadinessMode,
    /// Maximum `chain_tip - fully_scanned` block gap at which `/readyz` reports ready, in
    /// [`ReadinessMode::Synced`]. This height gap is the meaningful "caught up" signal:
    /// librustzcash's note-weighted progress ratio is over the *tip-priority* range and reaches
    /// 1.0 while lower-priority historical ranges are still being scanned, so a wallet can look
    /// "100% scanned" with `fully_scanned` far below the tip (e.g. a from-birthday restore).
    /// Gating on the height gap instead means `/readyz` only goes ready once the wallet has
    /// actually scanned to (near) the tip.
    pub max_scan_lag: u32,
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
    /// Where this wallet's `keys.toml` lives. `None` means the default location,
    /// `<dir>/keys.toml`; an explicit path (per-wallet `keys_file`, or the global
    /// `[keys] keys_file` / `ZECD_KEYS_FILE` for the default wallet) lets the encrypted seed
    /// be mounted as a Kubernetes Secret separately from the (disposable) data directory.
    pub keys_file: Option<PathBuf>,
    /// Shielded pools this wallet receives into and spends from (resolved per wallet).
    pub pools: PoolSet,
    /// Receivers included by default in this wallet's Unified Addresses (a subset of `pools`).
    pub default_receivers: PoolSet,
}

impl WalletEntry {
    /// The effective path to this wallet's `keys.toml` (the explicit `keys_file` override, or
    /// `<dir>/keys.toml` by default).
    pub fn keys_path(&self) -> PathBuf {
        self.keys_file
            .clone()
            .unwrap_or_else(|| self.dir.join("keys.toml"))
    }
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// The upstream server token: `zebra` (a local zebrad, the default) or
    /// `zebra://host:port` / `host:port`.
    pub server: String,
    /// Per-attempt dial timeout (seconds) for connecting to the backend endpoint.
    pub connect_timeout_secs: u64,
    /// Reconnect backoff base delay (seconds).
    pub reconnect_base_secs: u64,
    /// Reconnect backoff maximum delay (seconds).
    pub reconnect_max_secs: u64,
}

/// `[zebra]` - credentials for the `zebra://host:port` endpoint (direct-to-zebrad mode).
/// A cookie file wins over user/password, and nothing set means no auth (zebrad with
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
    /// additional accepted credential; generate them with `zecd rpcauth <user> [password]`.
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
    /// When true (the default), a wallet whose `keys.toml` is present but whose `data.sqlite`
    /// has no account is rebuilt from `keys.toml` on boot: the account is recreated from the
    /// seed (once available - immediately for identity/auto-unlock wallets, at first
    /// `walletpassphrase` for encrypted ones) and the wallet rescans from its birthday. Lets the
    /// data directory be a disposable cache while the seed lives in a mounted Secret. Set false
    /// to instead fail fast on an empty datadir.
    pub bootstrap_from_keys: bool,
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
    /// Cap on the number of Orchard actions (`max(orchard inputs, orchard outputs)`) a single
    /// send may build, mirroring Zallet's `[builder.limits] orchard_actions` (default 50). It
    /// bounds memory/proving cost and gives a clean `-8` instead of a deep librustzcash error
    /// when a `z_sendmany` has too many recipients. `0` disables the cap. Default 50.
    pub orchard_action_limit: usize,
    /// Build the Orchard proving key once at startup and prove sends through the PCZT roles,
    /// instead of librustzcash's fused `create_proposed_transactions` path which rebuilds the
    /// proving key (a full `keygen_vk`+`keygen_pk`) on *every* transaction. On by default;
    /// set `cache_proving_key = false` to fall back to the fused path (e.g. for benchmarking
    /// or if a PCZT issue is suspected). Both paths produce identical transactions.
    pub cache_proving_key: bool,
}

impl Default for SpendConfig {
    fn default() -> Self {
        Self {
            trusted_confirmations: 3,
            untrusted_confirmations: 10,
            privacy: SendPrivacy::AllowRevealedRecipients,
            orchard_action_limit: DEFAULT_ORCHARD_ACTION_LIMIT,
            cache_proving_key: true,
        }
    }
}

/// Default Orchard-action cap, matching Zallet's `orchard_actions` default.
pub const DEFAULT_ORCHARD_ACTION_LIMIT: usize = 50;

/// `[spend] privacy_policy` - Zallet/zcashd's privacy-policy idea (zcash/zcash#6240) reduced to
/// the two points that matter for a shielded-only wallet that can hold both Sapling and Orchard
/// notes: whether a send may include a transparent recipient, and whether it may cross between
/// shielded pools. Crossing pools (Sapling↔Orchard) reveals the transferred amount on-chain via
/// `valueBalance`; a transparent recipient additionally reveals the recipient. zcashd/Zallet
/// require an explicit `AllowRevealed*` opt-in for either, and this knob is zecd's equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPrivacy {
    /// Only fully-shielded transactions confined to a **single** shielded value pool: no
    /// transparent recipients, and no Sapling↔Orchard crossing. Such a send reveals neither the
    /// amount nor the recipient. (Enforced on the built proposal - see the actor's `do_send`.)
    FullPrivacy,
    /// Permits transparent recipients and cross-pool sends (which reveal the transferred amount,
    /// and the recipient if transparent). This is the default: the Bitcoin-RPC dialect promises
    /// "send to any valid address".
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
    sync: Option<SyncFile>,
    spend: Option<SpendFile>,
    pools: Option<PoolsFile>,
    health: Option<HealthFile>,
    log: Option<LogFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthFile {
    enabled: Option<bool>,
    bind: Option<String>,
    port: Option<u16>,
    readiness: Option<String>,
    max_scan_lag: Option<u32>,
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
    /// Path to this wallet's `keys.toml`, independent of `dir` (mount it as a Secret).
    keys_file: Option<PathBuf>,
    /// Override the global `[pools] enabled` for this wallet.
    pools: Option<Vec<String>>,
    /// Override the global `[pools] default_receivers` for this wallet.
    default_receivers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendFile {
    server: Option<String>,
    connect_timeout_secs: Option<u64>,
    reconnect_base_secs: Option<u64>,
    reconnect_max_secs: Option<u64>,
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
    /// Read the RPC password from this file (trailing newline trimmed) instead of inlining it.
    /// Lets the password - which is spend-equivalent for clients - live in a Kubernetes Secret
    /// rather than the ConfigMap the rest of the config lands in. Overrides `password`; the
    /// `--rpcpassword` flag / `ZECD_RPC_PASSWORD` env still win over both.
    password_file: Option<PathBuf>,
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
    /// Path to the default wallet's `keys.toml`, independent of the datadir (mount as a Secret).
    /// Equivalent to `[wallets.<default>] keys_file`; the `ZECD_KEYS_FILE` env / `--keys-file`
    /// flag override it.
    keys_file: Option<PathBuf>,
    /// Rebuild `data.sqlite` from `keys.toml` on an empty datadir (default true).
    bootstrap_from_keys: Option<bool>,
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
    orchard_action_limit: Option<usize>,
    cache_proving_key: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolsFile {
    enabled: Option<Vec<String>>,
    default_receivers: Option<Vec<String>>,
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

    /// RPC password (HTTP Basic auth). May also be supplied via `ZECD_RPC_PASSWORD` or
    /// `[rpc] password_file` so it need not live in the (ConfigMap-bound) TOML.
    #[arg(long = "rpcpassword", value_name = "PASS", env = "ZECD_RPC_PASSWORD")]
    pub rpc_password: Option<String>,

    /// rpcauth credential (`<user>:<salt>$<hmac-sha256 hex>`); may be repeated.
    #[arg(long = "rpcauth", value_name = "USER:SALT$HASH")]
    pub rpc_auth: Vec<String>,

    /// Chain upstream: `zebra` (local zebrad, the default) or `zebra://host:port`.
    #[arg(long, value_name = "SERVER")]
    pub server: Option<String>,

    /// age identity file used to decrypt the wallet seed for sending.
    #[arg(long, value_name = "FILE", env = "ZECD_AGE_IDENTITY")]
    pub age_identity: Option<PathBuf>,

    /// Path to the default wallet's `keys.toml`, independent of the datadir (so the encrypted
    /// seed can be a mounted Secret while the datadir stays a disposable cache).
    #[arg(long, value_name = "FILE", env = "ZECD_KEYS_FILE")]
    pub keys_file: Option<PathBuf>,

    /// Subcommand. When omitted, runs the daemon.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Create and initialize a new wallet (mnemonic + accounts), then exit.
    Init(InitArgs),
    /// Print a wallet's Unified Full Viewing Key (for pairing a watch-only instance via
    /// `init --ufvk`), then exit.
    ExportUfvk(ExportUfvkArgs),
    /// Generate a salted bitcoind-style `[rpc] auth` credential line (no external
    /// `rpcauth.py` needed), then exit.
    Rpcauth(RpcauthArgs),
    /// Run the JSON-RPC daemon (default).
    Run,
}

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Wallet name (selects/creates <datadir>/<name>).
    #[arg(long, default_value = "default")]
    pub wallet: String,

    /// Restore from an existing mnemonic instead of generating a new one. The phrase is read
    /// from `--mnemonic-file`, else the `ZECD_MNEMONIC` env var, else stdin.
    #[arg(long)]
    pub restore: bool,

    /// For `--restore`: read the mnemonic phrase from this file (trailing newline trimmed)
    /// instead of stdin, for non-interactive init. `ZECD_MNEMONIC` takes precedence.
    #[arg(long, value_name = "FILE")]
    pub mnemonic_file: Option<PathBuf>,

    /// Passphrase-encrypt the wallet (Bitcoin-Core style): the mnemonic is wrapped with a
    /// passphrase instead of the age identity, and the wallet starts locked - sending requires
    /// `walletpassphrase`. The passphrase is read from `ZECD_WALLET_PASSPHRASE` or stdin.
    #[arg(long)]
    pub encrypt: bool,

    /// Create a watch-only wallet from this Unified Full Viewing Key instead of a mnemonic
    /// (export it from the spending wallet with `export-ufvk`). The wallet sees balances,
    /// history, and addresses, but holds no spending material - spend and encryption RPCs
    /// are disabled.
    #[arg(long, value_name = "UFVK", conflicts_with_all = ["restore", "encrypt"])]
    pub ufvk: Option<String>,

    /// Optional birthday height; defaults to the current chain tip for new wallets.
    #[arg(long)]
    pub birthday: Option<u32>,
}

#[derive(Debug, clap::Args)]
pub struct RpcauthArgs {
    /// RPC username the credential is for.
    pub username: String,

    /// Password to hash. If omitted, a strong random password is generated and printed once.
    pub password: Option<String>,
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

        // keys.toml location override (so the encrypted seed can be a mounted Secret, separate
        // from the disposable datadir). The global `[keys] keys_file` / `ZECD_KEYS_FILE` /
        // `--keys-file` applies to the default wallet; a per-wallet `[wallets.<name>] keys_file`
        // overrides it for that wallet.
        let keys_file_global = cli
            .keys_file
            .clone()
            .or_else(|| file.keys.as_ref().and_then(|k| k.keys_file.clone()));

        // Global pool defaults (`[pools]`), validated before any per-wallet override.
        let pools = resolve_global_pools(file.pools.as_ref())?;

        // Wallets: from file, plus an implicit default if none declared. Each wallet's pools and
        // default receivers are resolved against the global `[pools]` defaults, with the same
        // subset validation applied per wallet.
        let mut wallets = BTreeMap::new();
        for (name, w) in &file.wallets {
            let dir = w.dir.clone().unwrap_or_else(|| datadir.join(name));
            let keys_file = w.keys_file.clone().or_else(|| {
                if name == &default_wallet {
                    keys_file_global.clone()
                } else {
                    None
                }
            });
            let (enabled, default_receivers) = resolve_wallet_pools(
                name,
                w.pools.as_deref(),
                w.default_receivers.as_deref(),
                &pools,
            )?;
            wallets.insert(
                name.clone(),
                WalletEntry {
                    dir,
                    keys_file,
                    pools: enabled,
                    default_receivers,
                },
            );
        }
        wallets
            .entry(default_wallet.clone())
            .or_insert_with(|| WalletEntry {
                dir: datadir.join(&default_wallet),
                keys_file: keys_file_global.clone(),
                pools: pools.enabled.clone(),
                default_receivers: pools.default_receivers.clone(),
            });

        let backend_file = file.backend.unwrap_or(BackendFile {
            server: None,
            connect_timeout_secs: None,
            reconnect_base_secs: None,
            reconnect_max_secs: None,
        });
        let server = select_server_token(cli.server.clone(), backend_file.server);
        let reconnect_base_secs = backend_file.reconnect_base_secs.unwrap_or(1).max(1);
        let backend = BackendConfig {
            server,
            connect_timeout_secs: backend_file.connect_timeout_secs.unwrap_or(10).max(1),
            reconnect_base_secs,
            reconnect_max_secs: backend_file
                .reconnect_max_secs
                .unwrap_or(60)
                .max(reconnect_base_secs),
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
            password_file: None,
            auth: None,
            cookiefile: None,
            work_queue: None,
            allowed_methods: None,
        });
        // RPC password precedence: `--rpcpassword` / `ZECD_RPC_PASSWORD` (clap) > `[rpc]
        // password_file` > inline `[rpc] password`. A configured `password_file` that can't be
        // read is fatal (fail fast rather than silently fall through to a weaker source).
        let password_from_file = rpc_file
            .password_file
            .as_deref()
            .map(read_secret_file)
            .transpose()?;
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
            password: cli
                .rpc_password
                .clone()
                .or(password_from_file)
                .or(rpc_file.password),
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
            keys_file: None,
            bootstrap_from_keys: None,
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
            bootstrap_from_keys: keys_file.bootstrap_from_keys.unwrap_or(true),
        };

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
            orchard_action_limit: spend_file
                .orchard_action_limit
                .unwrap_or(DEFAULT_ORCHARD_ACTION_LIMIT),
            cache_proving_key: spend_file.cache_proving_key.unwrap_or(true),
        };
        // Fail at startup, not on the first balance/send call.
        spend.confirmations_policy()?;

        let health_file = file.health.unwrap_or(HealthFile {
            enabled: None,
            bind: None,
            port: None,
            readiness: None,
            max_scan_lag: None,
        });
        let health = HealthConfig {
            enabled: health_file.enabled.unwrap_or(true),
            bind: health_file
                .bind
                .unwrap_or_else(|| "127.0.0.1".to_string())
                .parse()
                .context("parsing health bind address")?,
            port: health_file.port.unwrap_or(defaults.health_port),
            // Default to "connected": be generous about how synced we are so RPC clients can
            // reach zecd in most situations, and avoid readiness flapping during long scans.
            readiness: health_file
                .readiness
                .as_deref()
                .map(ReadinessMode::parse)
                .transpose()?
                .unwrap_or(ReadinessMode::Connected),
            max_scan_lag: health_file.max_scan_lag.unwrap_or(4),
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
            sync,
            spend,
            pools,
            health,
            log,
        })
    }
}

/// Resolve and validate the global `[pools]` section. `enabled` defaults to Orchard-only;
/// `default_receivers` defaults to the enabled set. The receivers must be a subset of the
/// enabled pools.
fn resolve_global_pools(file: Option<&PoolsFile>) -> anyhow::Result<PoolsConfig> {
    let enabled = match file.and_then(|f| f.enabled.as_deref()) {
        Some(tokens) => PoolSet::parse(tokens).context("[pools] enabled")?,
        None => PoolSet::single(Pool::Orchard),
    };
    let default_receivers = match file.and_then(|f| f.default_receivers.as_deref()) {
        Some(tokens) => PoolSet::parse(tokens).context("[pools] default_receivers")?,
        None => enabled.clone(),
    };
    if !default_receivers.is_subset_of(&enabled) {
        anyhow::bail!(
            "[pools] default_receivers ({}) must be a subset of enabled pools ({})",
            default_receivers.display_names(),
            enabled.display_names()
        );
    }
    Ok(PoolsConfig {
        enabled,
        default_receivers,
    })
}

/// Resolve and validate one wallet's pools/receivers against the global defaults. A wallet that
/// overrides `pools` but not `default_receivers` receives into all of its enabled pools by
/// default; a wallet that overrides neither inherits the global defaults.
fn resolve_wallet_pools(
    name: &str,
    pools: Option<&[String]>,
    default_receivers: Option<&[String]>,
    global: &PoolsConfig,
) -> anyhow::Result<(PoolSet, PoolSet)> {
    let enabled = match pools {
        Some(tokens) => {
            PoolSet::parse(tokens).with_context(|| format!("[wallets.{name}] pools"))?
        }
        None => global.enabled.clone(),
    };
    let receivers = match (default_receivers, pools) {
        (Some(tokens), _) => {
            PoolSet::parse(tokens).with_context(|| format!("[wallets.{name}] default_receivers"))?
        }
        // Wallet customized its pools but not its receivers: receive into everything it enabled.
        (None, Some(_)) => enabled.clone(),
        // Wallet customized neither: inherit the global default receivers.
        (None, None) => global.default_receivers.clone(),
    };
    if !receivers.is_subset_of(&enabled) {
        anyhow::bail!(
            "[wallets.{name}] default_receivers ({}) must be a subset of enabled pools ({})",
            receivers.display_names(),
            enabled.display_names()
        );
    }
    Ok((enabled, receivers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn global_pools_default_to_orchard_only() {
        let p = resolve_global_pools(None).unwrap();
        assert_eq!(p, PoolsConfig::default());
        assert!(p.enabled.contains(Pool::Orchard));
        assert!(!p.enabled.contains(Pool::Sapling));
        assert_eq!(p.default_receivers, p.enabled);
    }

    #[test]
    fn global_default_receivers_default_to_enabled() {
        let f = PoolsFile {
            enabled: Some(s(&["sapling", "orchard"])),
            default_receivers: None,
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(p.enabled.contains(Pool::Sapling) && p.enabled.contains(Pool::Orchard));
        // Receivers fall back to the full enabled set.
        assert_eq!(p.default_receivers, p.enabled);
    }

    #[test]
    fn global_receivers_must_be_subset_of_enabled() {
        let f = PoolsFile {
            enabled: Some(s(&["orchard"])),
            default_receivers: Some(s(&["sapling"])),
        };
        let err = resolve_global_pools(Some(&f)).unwrap_err().to_string();
        assert!(err.contains("subset"), "{err}");
        assert!(err.contains("sapling"), "{err}");
    }

    #[test]
    fn global_unknown_pool_is_rejected() {
        let f = PoolsFile {
            enabled: Some(s(&["ironwood"])),
            default_receivers: None,
        };
        let err = format!("{:#}", resolve_global_pools(Some(&f)).unwrap_err());
        assert!(
            err.contains("ironwood") || err.contains("unknown pool"),
            "{err}"
        );
    }

    #[test]
    fn global_empty_enabled_is_rejected() {
        let f = PoolsFile {
            enabled: Some(vec![]),
            default_receivers: None,
        };
        assert!(resolve_global_pools(Some(&f)).is_err());
    }

    #[test]
    fn wallet_inherits_global_when_unset() {
        let global = PoolsConfig {
            enabled: PoolSet::parse(&s(&["sapling", "orchard"])).unwrap(),
            default_receivers: PoolSet::single(Pool::Orchard),
        };
        let (enabled, receivers) = resolve_wallet_pools("w", None, None, &global).unwrap();
        assert_eq!(enabled, global.enabled);
        assert_eq!(receivers, global.default_receivers);
    }

    #[test]
    fn wallet_overriding_pools_defaults_receivers_to_its_enabled() {
        // A wallet that narrows its pools but doesn't set receivers must not inherit the global
        // receivers (which could name a now-disabled pool) - it receives into all it enabled.
        let global = PoolsConfig::default(); // orchard-only
        let (enabled, receivers) =
            resolve_wallet_pools("w", Some(&s(&["sapling"])), None, &global).unwrap();
        assert!(enabled.contains(Pool::Sapling) && !enabled.contains(Pool::Orchard));
        assert_eq!(receivers, enabled);
    }

    #[test]
    fn wallet_receivers_not_subset_of_enabled_is_rejected() {
        let global = PoolsConfig::default();
        let err = resolve_wallet_pools(
            "hot",
            Some(&s(&["orchard"])),
            Some(&s(&["sapling"])),
            &global,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("wallets.hot"), "{err}");
        assert!(err.contains("subset"), "{err}");
    }

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
    fn orchard_action_limit_defaults_and_parses() {
        // Absent → the Zallet-matching default of 50.
        assert_eq!(SpendConfig::default().orchard_action_limit, 50);
        assert_eq!(DEFAULT_ORCHARD_ACTION_LIMIT, 50);
        // Explicit value (including 0, which disables the cap) round-trips.
        let f: SpendFile = toml::from_str("orchard_action_limit = 200").unwrap();
        assert_eq!(f.orchard_action_limit, Some(200));
        let f: SpendFile = toml::from_str("orchard_action_limit = 0").unwrap();
        assert_eq!(f.orchard_action_limit, Some(0));
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
        // CLI wins over the file `server`.
        assert_eq!(
            select_server_token(Some("cli:1".into()), Some("str:1".into())),
            "cli:1".to_string()
        );
        // The file `server` is used when there's no CLI flag.
        assert_eq!(
            select_server_token(None, Some("str:1".into())),
            "str:1".to_string()
        );
        // Nothing configured -> built-in default (a local zebrad).
        assert_eq!(select_server_token(None, None), DEFAULT_SERVER.to_string());
    }

    #[test]
    fn backend_file_parses_server_and_backoff() {
        let f: BackendFile = toml::from_str(
            r#"
            server = "zebra://127.0.0.1:18234"
            connect_timeout_secs = 5
            reconnect_base_secs = 2
            reconnect_max_secs = 30
            "#,
        )
        .unwrap();
        assert_eq!(f.server.as_deref(), Some("zebra://127.0.0.1:18234"));
        assert_eq!(f.connect_timeout_secs, Some(5));
        assert_eq!(f.reconnect_base_secs, Some(2));
        assert_eq!(f.reconnect_max_secs, Some(30));
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
    fn read_secret_file_trims_trailing_newline_only() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pw");
        // The classic `echo "secret" > file` leaves a trailing newline; it must be stripped,
        // but interior/leading whitespace is preserved (a password may legitimately contain it).
        std::fs::write(&p, "  hunter2 spaces \n").unwrap();
        assert_eq!(read_secret_file(&p).unwrap(), "  hunter2 spaces ");
        // A missing file is an error (fail fast), not an empty password.
        assert!(read_secret_file(&dir.path().join("nope")).is_err());
    }

    #[test]
    fn rpc_password_file_is_read_and_overridden_by_cli() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let pw = dir.path().join("rpc.pw");
        std::fs::write(&pw, "from-file\n").unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            format!(
                "network = \"test\"\n[rpc]\nuser = \"u\"\npassword = \"inline\"\npassword_file = \"{}\"\n",
                pw.display()
            ),
        )
        .unwrap();

        // password_file overrides the inline [rpc] password...
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.rpc.password.as_deref(), Some("from-file"));

        // ...but an explicit --rpcpassword still wins over the file.
        let cli = Cli::parse_from([
            "zecd",
            "--conf",
            conf.to_str().unwrap(),
            "--rpcpassword",
            "from-cli",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.rpc.password.as_deref(), Some("from-cli"));

        // A configured-but-missing password_file is a startup error.
        std::fs::write(
            &conf,
            "network = \"test\"\n[rpc]\npassword_file = \"/no/such/rpc.pw\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        assert!(AppConfig::resolve(&cli).is_err());
    }

    #[test]
    fn keys_file_override_resolves_per_wallet() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        // Default: keys.toml lives under the wallet's dir.
        std::fs::write(&conf, "network = \"test\"\ndatadir = \"/d\"\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.wallets["default"].keys_path(),
            PathBuf::from("/d/default/keys.toml")
        );

        // Global [keys] keys_file applies to the default wallet; a per-wallet override wins for
        // the named wallet and the global doesn't leak onto non-default wallets.
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n\
             [keys]\nkeys_file = \"/secrets/keys.toml\"\n\
             [wallets.other]\nkeys_file = \"/secrets/other.toml\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.wallets["default"].keys_path(),
            PathBuf::from("/secrets/keys.toml")
        );
        assert_eq!(
            cfg.wallets["other"].keys_path(),
            PathBuf::from("/secrets/other.toml")
        );

        // --keys-file overrides the file's global keys_file for the default wallet.
        let cli = Cli::parse_from([
            "zecd",
            "--conf",
            conf.to_str().unwrap(),
            "--keys-file",
            "/cli/keys.toml",
        ]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(
            cfg.wallets["default"].keys_path(),
            PathBuf::from("/cli/keys.toml")
        );
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
