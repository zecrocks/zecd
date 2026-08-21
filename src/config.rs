//! Daemon configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].
//!
//! CLI flags use Bitcoin-Core-style names (`-rpcuser`, `-rpcport`, `-datadir`, `-testnet`)
//! where it helps operators, but the canonical source is the TOML config.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::Context;
#[cfg(feature = "cli")]
use clap::Parser;
use serde::Deserialize;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

use crate::coin::{Coin, CoinNetwork};
use crate::network::ZNetwork;
use crate::pools::{Receiver, ReceiverSet};

/// Default chain upstream: a local zebrad's JSON-RPC ("full mode"). Public keeps the bare
/// `zebra` shorthand as the default rather than spelling the authority out; `backend::resolve`
/// expands it to `127.0.0.1:8234` on mainnet / `:18234` on testnet and regtest (see
/// `backend::ZEBRA_RPC_PORT_*`). A zebrad on another host/port is
/// `[backend] server = "zebra://host:port"`, and `backend::resolve` documents the full token
/// grammar including the light-mode forms.
pub const DEFAULT_SERVER: &str = "zebra";

/// The built-in `server` token for `network`, used when neither `--server` nor `[backend]
/// server` is set. Network-independent here, since the shorthand resolves per network.
/// (`backend::tests::default_server_resolves_to_local_zebrad_per_network` pins that.)
pub fn default_server(_network: ZNetwork) -> &'static str {
    DEFAULT_SERVER
}

/// The default directory for wallet `name`: `<datadir>/<name>`.
///
/// A wallet directory holds `keys.toml` - the one file in it that is zecd's own, and the only
/// one a from-seed restore cannot rebuild - plus one subdirectory per coin ([`coin_dir`]).
/// The data directory itself holds only daemon-level files (`zecd.toml`, `.lock`, `.cookie`,
/// `identity.txt`).
///
/// A `[wallets.<name>] dir` override replaces this outright; everything below is still laid
/// out inside whatever path the operator names.
pub fn wallet_dir(datadir: &Path, name: &str) -> PathBuf {
    datadir.join(name)
}

/// Where `coin`'s state lives inside a wallet directory: `<wallet dir>/zec` for Zcash
/// ([`Coin::data_dir`]).
///
/// The seed in `keys.toml` serves every coin, so the coin sits *inside* the wallet rather than
/// above it: one wallet, one seed, one subdirectory per coin underneath.
pub fn coin_dir(wallet_dir: &Path, coin: Coin) -> PathBuf {
    wallet_dir.join(coin.data_dir())
}

/// Where the wallet-storage engine's own files live: `<wallet dir>/zec/lrz` for Zcash, holding
/// everything librustzcash owns - `data.sqlite`, `blockmeta.sqlite`, `blocks/`
/// ([`Coin::engine_dir`]).
///
/// Nothing outside these three functions and [`crate::migrate`] should join a coin or engine
/// directory name onto a path: callers take a wallet directory from [`WalletEntry::dir`] and an
/// engine directory from [`WalletEntry::engine_dir`].
pub fn engine_dir(wallet_dir: &Path, coin: Coin) -> PathBuf {
    coin_dir(wallet_dir, coin).join(coin.engine_dir())
}

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
    pub enabled: ReceiverSet,
    /// Receivers included in the UAs handed out by `getnewaddress` when no per-call override is
    /// given. Always a subset of `enabled`.
    pub default_receivers: ReceiverSet,
    /// Whether the wallet may hand out bare transparent (`t1…`/`tm…`) receiving addresses - via
    /// `getnewaddress "" "transparent"`, and (when `transparent_default`) as the no-argument
    /// default. Off preserves zecd's shielded-only behaviour: `address_type = "transparent"` is
    /// rejected `-8`. Received transparent UTXOs are spendable only by auto-shielding them into a
    /// shielded send.
    pub transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` returns a bare transparent address instead of a
    /// Unified Address. Requires `transparent_enabled` (validated at parse time).
    pub transparent_default: bool,
    /// The **external** transparent gap limit: how far past the last *funded* receiving address a
    /// stateless restore keeps scanning the address index before giving up. Sized to the maximum
    /// number of addresses the operator may hand out ahead of funding - a higher value lets a
    /// rebuilt (stateless) wallet rediscover transparent funds across sparsely-funded
    /// pre-generated addresses, at the cost of more address-index queries per restore/scan. Only
    /// meaningful when `transparent_enabled`.
    pub transparent_gap_limit: u32,
    /// **Initial scan depth.** On startup/restore, pre-expose external transparent indices
    /// `0..transparent_initial_scan` so the wallet scans *all* of them for receives - independent
    /// of (and typically far larger than) `transparent_gap_limit`. This is the initial-scan lever: an
    /// exchange that hands out, say, 10 000 addresses sets this to 10 000 so a stateless restore
    /// rediscovers a payment to any of them, while keeping a small steady-state `gap_limit` (it
    /// does *not* want a 10 000-deep sliding window past every funded address). `0` (the default)
    /// means no pre-exposure - discovery is bounded by `gap_limit` alone. Only meaningful when
    /// `transparent_enabled`.
    pub transparent_initial_scan: u32,
    /// Whether `getnewaddress "" "transparent"` may keep issuing receiving addresses **past** the
    /// recovery window (`transparent_gap_limit` consecutive unfunded addresses, plus the
    /// `transparent_initial_scan` floor). librustzcash fails closed at the gap limit; with this set
    /// (the default) zecd issues beyond it anyway, logging a loud warning that funds received at
    /// such an address may be unrecoverable from seed. Set `false` to instead fail the call with an
    /// actionable error. Only meaningful when `transparent_enabled`.
    pub transparent_allow_beyond_recovery_window: bool,
    /// Warn (once per `getnewaddress`) when fewer than this many transparent address slots remain
    /// inside the recovery window before generation would hit the gap limit. Lets an operator widen
    /// `transparent_gap_limit`/`transparent_initial_scan` (or fund a lower index) before addresses
    /// start landing outside the window. `0` warns only on actual exhaustion. Only meaningful when
    /// `transparent_enabled`.
    pub transparent_gap_warn_threshold: u32,
}

/// Default external transparent gap limit. Above librustzcash's built-in 10 to give a safer margin
/// for typical sparse issuance, while keeping restore scans cheap.
pub const DEFAULT_TRANSPARENT_GAP_LIMIT: u32 = 20;

/// Hard upper bound on `transparent_gap_limit`, enforced at config validation. The gap window is
/// not just a scan bound: librustzcash's gap maintenance re-derives the ENTIRE window - a full
/// unified-address derivation per index - every time a transparent receive is recorded
/// (`put_received_transparent_utxo` -> `update_gap_limits`), and repeats that regeneration once
/// per already-recorded output of the same transaction. At the measured ~1.2k derivations/s a
/// 71000-wide window costs about a minute per received UTXO (quadratically more for multi-output
/// transactions), all on the single-writer actor inside the sync batch - in the field this
/// presented as a restore "stalled" >100x, one core pegged, with the block scan frozen for hours
/// (zecd 0.5.1-rc2 report, 2026-07-30). Deep restore coverage belongs to
/// `transparent_initial_scan` (a one-time pre-exposure, not a per-receive cost); the gap limit
/// only needs to cover outstanding unfunded handed-out addresses. Above 10 000 the worst-case
/// per-receive cost passes ~10s, far beyond any sane outstanding-handout count - but the value
/// stays the operator's choice: the daemon starts anyway and logs at error level (an
/// operator-facing knob is never a hard failure when the misconfiguration only costs
/// performance).
pub const TRANSPARENT_GAP_LIMIT_SEVERE: u32 = 10_000;

/// Soft bound on `transparent_gap_limit` above which the daemon logs a startup warning (see
/// [`TRANSPARENT_GAP_LIMIT_SEVERE`] for the cost mechanism): ~1s of address derivation per
/// recorded transparent receive, more for multi-output transactions.
pub const TRANSPARENT_GAP_LIMIT_COSTLY: u32 = 1_000;

/// Default for `transparent_allow_beyond_recovery_window`: permissive (warn, don't block), matching
/// the Bitcoin-RPC promise that `getnewaddress` keeps handing out addresses.
pub const DEFAULT_TRANSPARENT_ALLOW_BEYOND: bool = true;

/// Default for `transparent_gap_warn_threshold`: warn once the last few in-window slots remain.
pub const DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD: u32 = 5;

impl Default for PoolsConfig {
    fn default() -> Self {
        // Preserves zecd's historical behaviour: Orchard-only receiving, no transparent.
        Self {
            enabled: ReceiverSet::single(Receiver::Orchard),
            default_receivers: ReceiverSet::single(Receiver::Orchard),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: DEFAULT_TRANSPARENT_GAP_LIMIT,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: DEFAULT_TRANSPARENT_ALLOW_BEYOND,
            transparent_gap_warn_threshold: DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD,
        }
    }
}

/// What `/readyz` means - chosen to fit a deployment's priorities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessMode {
    /// Ready only once the wallet has actually scanned to (near) the chain tip: connected and
    /// within `max_scan_lag` blocks of the tip. Strict - a from-birthday restore stays "not
    /// ready" until it catches up. **This is the default**: a client must not see an empty or
    /// stale balance/history as authoritative while the wallet is still scanning.
    Synced,
    /// Ready as soon as the backend is connected and its chain tip is past the wallet's birthday
    /// (a cheap sanity check that we're talking to the right, live network). Does NOT wait for
    /// the wallet to finish scanning, so RPC clients can reach zecd while it catches up - at the
    /// cost of reads possibly lagging the tip. Avoids readiness flapping during long scans. Opt in
    /// (`readiness = "connected"`) only when reachability matters more than balance freshness.
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
    /// The coin this wallet serves.
    pub coin: Coin,
    /// This wallet's chain, derived from (its coin, the daemon's network environment). Not a
    /// config key: `--testnet`/`--regtest` set the environment for the whole daemon and every
    /// wallet's chain follows from it, so a wallet on the wrong network is unrepresentable.
    pub chain: CoinNetwork,
    /// This wallet's overrides of the global `[backend]` endpoint settings.
    pub backend: WalletBackendOverride,
    /// Shielded pools this wallet receives into and spends from (resolved per wallet).
    pub pools: ReceiverSet,
    /// Receivers included by default in this wallet's Unified Addresses (a subset of `pools`).
    pub default_receivers: ReceiverSet,
    /// Whether this wallet may hand out bare transparent receiving addresses (resolved per wallet).
    pub transparent_enabled: bool,
    /// Whether a no-argument `getnewaddress` on this wallet returns a bare transparent address.
    pub transparent_default: bool,
    /// This wallet's external transparent gap limit (see [`PoolsConfig::transparent_gap_limit`]).
    pub transparent_gap_limit: u32,
    /// This wallet's initial transparent scan depth (see [`PoolsConfig::transparent_initial_scan`]).
    pub transparent_initial_scan: u32,
    /// Whether this wallet may issue transparent addresses past the recovery window
    /// (see [`PoolsConfig::transparent_allow_beyond_recovery_window`]).
    pub transparent_allow_beyond_recovery_window: bool,
    /// This wallet's remaining-slot warning threshold
    /// (see [`PoolsConfig::transparent_gap_warn_threshold`]).
    pub transparent_gap_warn_threshold: u32,
}

impl WalletEntry {
    /// This wallet's Zcash network.
    ///
    /// Unwrapped at the call site rather than stored bare, so the daemon-global
    /// `config.network` and a wallet's own chain stay distinguishable: the reads that mean
    /// "this deployment" keep using the former, and the per-wallet ones go through here.
    pub fn zcash_network(&self) -> ZNetwork {
        match self.chain {
            CoinNetwork::Zcash(network) => network,
        }
    }

    /// This wallet's engine directory: everything librustzcash owns, at
    /// `<dir>/<coin>/<engine>` (see [`engine_dir`]). This - not [`WalletEntry::dir`] - is what
    /// the wallet database, the block cache, and every read path are opened against.
    pub fn engine_dir(&self) -> PathBuf {
        engine_dir(&self.dir, self.coin)
    }

    /// The effective path to this wallet's `keys.toml` (the explicit `keys_file` override, or
    /// `<dir>/keys.toml` by default).
    ///
    /// It sits at the wallet root, above the per-coin directories: the BIP-39 seed it wraps
    /// serves every coin, and it is the one file here that no engine swap or rescan may touch.
    pub fn keys_path(&self) -> PathBuf {
        self.keys_file
            .clone()
            .unwrap_or_else(|| self.dir.join("keys.toml"))
    }
}

/// A wallet's per-endpoint overrides of the global `[backend]` section.
///
/// Only the settings that describe *which upstream this wallet dials* are overridable:
/// the server token and the TLS trust that authenticates it. Daemon policy - timeouts,
/// reconnect backoff, the cleartext-locality rules - and the `[zebra]` credentials stay
/// global, because they are properties of the deployment rather than of one endpoint.
///
/// Every field is `None` when the wallet does not override it, which is also what
/// `config show` renders by: a wallet with no overrides emits no backend keys at all, and
/// falls back to `[backend]`.
#[derive(Debug, Clone, Default)]
pub struct WalletBackendOverride {
    /// See [`BackendConfig::server`].
    pub server: Option<String>,
    /// See [`BackendConfig::tls`]. The outer `Option` is "did the wallet override it"; the
    /// inner one is the tri-state TLS mode (`None` = auto).
    pub tls: Option<Option<bool>>,
    /// See [`BackendConfig::tls_roots`].
    pub tls_roots: Option<crate::backend::TlsRoots>,
    /// See [`BackendConfig::tls_insecure_skip_verify`].
    pub tls_insecure_skip_verify: Option<bool>,
    /// See [`BackendConfig::tls_ca_pem`]. Read at config load, like the global key.
    pub tls_ca_pem: Option<Vec<u8>>,
    /// See [`BackendConfig::tls_ca_file`] - kept so the setting can be reported by its key.
    pub tls_ca_file: Option<PathBuf>,
    /// See [`BackendConfig::tls_pins`].
    pub tls_pins: Option<Vec<crate::backend::CertFingerprint>>,
    /// See [`BackendConfig::assume_transparent_in_compact_blocks`].
    pub assume_transparent_in_compact_blocks: Option<bool>,
}

impl WalletBackendOverride {
    /// Whether this wallet overrides anything at all (used to skip duplicate reporting of an
    /// endpoint that is just the global one).
    pub fn is_empty(&self) -> bool {
        self.server.is_none()
            && self.tls.is_none()
            && self.tls_roots.is_none()
            && self.tls_insecure_skip_verify.is_none()
            && self.tls_ca_pem.is_none()
            && self.tls_pins.is_none()
            && self.assume_transparent_in_compact_blocks.is_none()
    }

    /// The effective backend settings for this wallet: the global `[backend]` with this
    /// wallet's overrides applied. Field-by-field, so a wallet that overrides only `server`
    /// keeps every global TLS setting.
    pub fn effective(&self, global: &BackendConfig) -> BackendConfig {
        BackendConfig {
            server: self.server.clone().unwrap_or_else(|| global.server.clone()),
            tls: self.tls.unwrap_or(global.tls),
            tls_roots: self.tls_roots.unwrap_or(global.tls_roots),
            tls_insecure_skip_verify: self
                .tls_insecure_skip_verify
                .unwrap_or(global.tls_insecure_skip_verify),
            tls_ca_pem: self
                .tls_ca_pem
                .clone()
                .or_else(|| global.tls_ca_pem.clone()),
            tls_ca_file: self
                .tls_ca_file
                .clone()
                .or_else(|| global.tls_ca_file.clone()),
            tls_pins: self
                .tls_pins
                .clone()
                .unwrap_or_else(|| global.tls_pins.clone()),
            assume_transparent_in_compact_blocks: self
                .assume_transparent_in_compact_blocks
                .unwrap_or(global.assume_transparent_in_compact_blocks),
            // Daemon policy, never per-wallet.
            connect_timeout_secs: global.connect_timeout_secs,
            reconnect_base_secs: global.reconnect_base_secs,
            reconnect_max_secs: global.reconnect_max_secs,
            rfc1918_is_local: global.rfc1918_is_local,
            allow_remote_cleartext: global.allow_remote_cleartext,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendConfig {
    /// The upstream server token: `zebra` (a local zebrad, the default),
    /// `zebra://host:port`, the `zecrocks` public-lightwalletd preset, or a lightwalletd
    /// endpoint (`https://host[:port]` / `http://host:port` / bare `host:port`).
    pub server: String,
    /// Per-attempt dial timeout (seconds) for connecting to the backend endpoint.
    pub connect_timeout_secs: u64,
    /// Reconnect backoff base delay (seconds).
    pub reconnect_base_secs: u64,
    /// Reconnect backoff maximum delay (seconds).
    pub reconnect_max_secs: u64,
    /// Treat private / non-globally-routable ranges (RFC1918, link-local, CGNAT, IPv6 unique-local
    /// and link-local) as "local" for the cleartext-credential gate, so a credentialed connect to
    /// a container/LAN zebra is allowed without an override. Default `true` (the self-hosted
    /// `zebra -> zecd` Docker/LAN norm); set `false` for a strict loopback-only posture.
    pub rfc1918_is_local: bool,
    /// Escape hatch for the cleartext-credential gate: allow the (plaintext) zebra connection to
    /// carry RPC credentials to *any* host, including globally-routable ones. Off by default; the
    /// gate otherwise refuses a globally-routable host, since the credentials travel in cleartext.
    /// Set this only when the hop to a remote zebra is secured out-of-band (SSH/WireGuard tunnel,
    /// private overlay).
    pub allow_remote_cleartext: bool,
    /// lightwalletd TLS mode: `None` ("auto", the default) uses the locality heuristic
    /// (loopback/private plaintext, public TLS); `Some(true/false)` forces it. Ignored by
    /// `zebra://` endpoints (always plaintext) and overridden per-endpoint by an explicit
    /// `https://`/`http://` scheme.
    pub tls: Option<bool>,
    /// Which root certificates lightwalletd TLS trusts (`native` = OS store, the default;
    /// `webpki` = the embedded Mozilla bundle).
    pub tls_roots: crate::backend::TlsRoots,
    /// Accept *any* lightwalletd TLS certificate - no chain-of-trust or hostname check. Off by
    /// default. The connection stays encrypted but is no longer authenticated, so an on-path
    /// attacker can impersonate the server and observe every address and txid this wallet asks
    /// about. `tls_pinned_sha256` is the better answer for a self-signed certificate: it
    /// authenticates the server rather than giving up on doing so.
    pub tls_insecure_skip_verify: bool,
    /// PEM contents of a private CA to trust for lightwalletd TLS (`tls_ca_file`), read at
    /// config load. Added to the public roots, so a private-CA-issued certificate validates
    /// normally - hostname and expiry included.
    pub tls_ca_pem: Option<Vec<u8>>,
    /// Where [`tls_ca_pem`](Self::tls_ca_pem) was read from. Kept alongside the bytes purely so
    /// the setting can be *reported* by its key (`zecd config show` renders the effective
    /// configuration in its own TOML syntax, and a PEM blob is not a value that can be written
    /// back as `tls_ca_file`). Nothing on the connect path reads it.
    pub tls_ca_file: Option<PathBuf>,
    /// Acceptable lightwalletd leaf-certificate SHA-256 fingerprints (`tls_pinned_sha256`).
    /// Non-empty pins the connection to those certificates; combined with `tls_ca_file` the
    /// chain is validated against that CA as well.
    pub tls_pins: Vec<crate::backend::CertFingerprint>,
    /// Operator assertion that the upstream lightwalletd serves transparent (and ironwood) data
    /// inside compact blocks, overriding the `GetLightdInfo.lightwalletProtocolVersion` probe.
    ///
    /// The probe exists because a server that cannot serve that data would silently never
    /// discover transparent receives. But no released lightwalletd populates the field yet - it
    /// is specified in the lightwallet protocol and left empty by the reference implementation -
    /// so the probe reports "incapable" even for a 0.5.x server that does serve the data. This
    /// knob is the operator's way to say "I know what my server does". Off by default: guessing
    /// wrong reintroduces exactly the silent-loss failure the probe is there to prevent.
    ///
    /// Ignored by `zebra://` endpoints, which always cover transparent data.
    pub assume_transparent_in_compact_blocks: bool,
}

impl BackendConfig {
    /// The resolved TLS settings for the lightwalletd dial.
    pub fn tls_options(&self) -> crate::backend::TlsOptions {
        crate::backend::TlsOptions {
            force_tls: self.tls,
            roots: self.tls_roots,
            insecure_skip_verify: self.tls_insecure_skip_verify,
            ca_pem: self.tls_ca_pem.clone(),
            pins: self.tls_pins.clone(),
        }
    }
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
#[non_exhaustive]
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
    /// Accept a repeated *shielded* recipient in one `z_sendmany` call (default false).
    ///
    /// zcashd rejects any duplicate recipient address, and zecd matches that by default: this
    /// is a zcashd-dialect method, and quietly accepting input a client was written against a
    /// refusal for is how bugs get baked in. But nothing in consensus or the wallet forbids two
    /// shielded outputs paying one address - it is how a batch of memo-carrying payments to a
    /// single address rides in one transaction, for one ZIP-317 fee - so an operator running
    /// such a protocol can opt in here. Transparent duplicates stay refused whatever this is
    /// set to: Bitcoin Core dedupes them for reasons of its own in history accounting, and
    /// nothing asked for that to change.
    ///
    /// Embedded callers need no knob: [`crate::node::Node::send`] takes a
    /// `zip321::TransactionRequest`, which expresses repeated recipients natively.
    pub allow_duplicate_shielded_recipients: bool,
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
    /// Run a send's proving step *off* the single-writer actor so it no longer freezes the
    /// background sync (and reads/status/mempool) for the whole proof - which, on a large,
    /// note-fragmented wallet, can be many minutes. The actor still serializes sends (only one
    /// proof is uncommitted at a time, so there is no double-spend surface and no reservation
    /// overlay); the win is that sync stays live while the proof runs on a blocking thread.
    /// Only engages on the cached-Orchard PCZT path (an Orchard-only wallet with
    /// `cache_proving_key` on); a Sapling-spending wallet keeps the inline fused path. **Off by
    /// default** - flip it on once validated by the funded/stress regtest tiers.
    pub pipeline_proving: bool,
}

impl Default for SpendConfig {
    fn default() -> Self {
        Self {
            trusted_confirmations: 3,
            untrusted_confirmations: 10,
            privacy: SendPrivacy::AllowRevealedRecipients,
            orchard_action_limit: DEFAULT_ORCHARD_ACTION_LIMIT,
            cache_proving_key: true,
            pipeline_proving: false,
        }
    }
}

/// Default Orchard-action cap, matching Zallet's `orchard_actions` default.
pub const DEFAULT_ORCHARD_ACTION_LIMIT: usize = 50;

/// `[spend] privacy_policy` - Zallet/zcashd's privacy-policy idea (zcash/zcash#6240) reduced to
/// the leaks a zecd send can actually cause: whether a send may cross between shielded pools
/// (Sapling↔Orchard, revealing the transferred amount on-chain via `valueBalance`), whether it
/// may include a transparent recipient (additionally revealing the recipient), whether it may be
/// *funded* from the wallet's transparent UTXOs (revealing the sender's addresses and input
/// amounts - `z_sendmany`'s transparent `fromaddress`/`ANY_TADDR` coin control), and whether the
/// change of such a send may stay transparent (a fully transparent spend). zcashd/Zallet require
/// an explicit `AllowRevealed*` opt-in for each, and this knob is zecd's equivalent: a five-rung
/// ladder - `FullPrivacy` < `AllowRevealedAmounts` < `AllowRevealedRecipients` <
/// `AllowRevealedSenders` < `AllowFullyTransparent`. Unlike zcashd's policy lattice the ladder is
/// linear, so each rung implies everything below it (`AllowRevealedSenders` here permits
/// transparent recipients too, where zcashd keeps senders and recipients orthogonal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendPrivacy {
    /// Only fully-shielded transactions confined to a **single** shielded value pool: no
    /// transparent recipients, and no Sapling↔Orchard crossing. Such a send reveals neither the
    /// amount nor the recipient. (Enforced on the built proposal - see the actor's `do_send`.)
    FullPrivacy,
    /// Permits crossing the Sapling↔Orchard turnstile (which reveals the transferred *amount*
    /// on-chain via `valueBalance`) but **not** a transparent recipient (which would additionally
    /// reveal the *recipient*). This is zcashd's `AllowRevealedAmounts`, the policy one notch
    /// weaker than `FullPrivacy`: a caller who opts into revealing amounts has not thereby opted
    /// into revealing recipients.
    AllowRevealedAmounts,
    /// Permits transparent recipients and cross-pool sends (which reveal the transferred amount,
    /// and the recipient if transparent). This is the default: the Bitcoin-RPC dialect promises
    /// "send to any valid address". A transparent recipient is paid from shielded notes, so the
    /// *sender* side stays shielded; the wallet's leftover change also stays shielded.
    AllowRevealedRecipients,
    /// Additionally permits funding a send from the wallet's received transparent (t-address)
    /// UTXOs - `z_sendmany` with a transparent `fromaddress` or `ANY_TADDR` - which reveals the
    /// sender's addresses and input amounts on-chain. The change of such a send is **shielded**
    /// (it goes to the wallet's shielded change pool), so a send from a t-address to a shielded
    /// recipient under this rung is the t->z *shielding* send. Kept-transparent change (a fully
    /// transparent spend) still requires `AllowFullyTransparent`. Mirrors zcashd's
    /// `AllowRevealedSenders`, except zecd's linear ladder means this rung also permits
    /// transparent recipients (paid from shielded notes when the source is shielded).
    AllowRevealedSenders,
    /// Additionally permits a **fully transparent** spend: funding a send directly from the
    /// wallet's received transparent (t-address) UTXOs, with the change kept transparent - the
    /// most revealing send possible (amount, sender UTXOs, recipient, and change are all public,
    /// and never touch a shielded pool). Strictly opt-in; this is the only policy under which
    /// transparent change is possible. Mirrors zcashd/Zallet
    /// `AllowFullyTransparent`/`NoPrivacy`.
    AllowFullyTransparent,
}

impl SendPrivacy {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "FullPrivacy" => Ok(Self::FullPrivacy),
            "AllowRevealedAmounts" => Ok(Self::AllowRevealedAmounts),
            "AllowRevealedRecipients" => Ok(Self::AllowRevealedRecipients),
            "AllowRevealedSenders" => Ok(Self::AllowRevealedSenders),
            "AllowFullyTransparent" => Ok(Self::AllowFullyTransparent),
            other => anyhow::bail!(
                "[spend] privacy_policy must be \"FullPrivacy\", \"AllowRevealedAmounts\", \
                 \"AllowRevealedRecipients\", \"AllowRevealedSenders\", or \
                 \"AllowFullyTransparent\" (got \"{other}\")"
            ),
        }
    }

    /// recipient and the amount on-chain. `AllowRevealedRecipients` and every rung above it
    /// (`AllowRevealedSenders`, `AllowFullyTransparent` - the ladder is linear, each rung implies
    /// the ones below) permit a transparent recipient; `FullPrivacy` and `AllowRevealedAmounts`
    /// reject one (the latter opts into revealed *amounts* only). Omitting `AllowFullyTransparent`
    /// here would make the fully-transparent send path unreachable - the `build_payment` pre-check
    /// would `-8`-reject the recipient before the t->t spend could run.
    pub fn allows_transparent_recipient(self) -> bool {
        matches!(
            self,
            Self::AllowRevealedRecipients
                | Self::AllowRevealedSenders
                | Self::AllowFullyTransparent
        )
    }

    /// Whether a send under this policy may be *funded* from the wallet's transparent UTXOs
    /// (`z_sendmany` with a transparent `fromaddress`/`ANY_TADDR`), revealing the sender's
    /// addresses and input amounts on-chain. This is the gate for spending transparent inputs at
    /// all; the kept-transparent-change t->t path additionally requires `AllowFullyTransparent`
    /// (under `AllowRevealedSenders` the change of a transparent-funded send is shielded).
    pub fn allows_transparent_inputs(self) -> bool {
        matches!(
            self,
            Self::AllowRevealedSenders | Self::AllowFullyTransparent
        )
    }

    /// The zcashd `privacyPolicy` name for this policy, used in the self-diagnosing send errors.
    pub fn policy_name(self) -> &'static str {
        match self {
            Self::FullPrivacy => "FullPrivacy",
            Self::AllowRevealedAmounts => "AllowRevealedAmounts",
            Self::AllowRevealedRecipients => "AllowRevealedRecipients",
            Self::AllowRevealedSenders => "AllowRevealedSenders",
            Self::AllowFullyTransparent => "AllowFullyTransparent",
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
    /// Override the global `[backend] server` for this wallet.
    server: Option<String>,
    /// Override the global `[backend] tls` for this wallet.
    tls: Option<String>,
    /// Override the global `[backend] tls_roots` for this wallet.
    tls_roots: Option<String>,
    /// Override the global `[backend] tls_insecure_skip_verify` for this wallet.
    tls_insecure_skip_verify: Option<bool>,
    /// Override the global `[backend] tls_ca_file` for this wallet.
    tls_ca_file: Option<PathBuf>,
    /// Override the global `[backend] tls_pinned_sha256` for this wallet.
    tls_pinned_sha256: Option<Vec<String>>,
    /// Override the global `[backend] assume_transparent_in_compact_blocks` for this wallet.
    assume_transparent_in_compact_blocks: Option<bool>,
    /// Override the global `[pools] enabled` for this wallet.
    pools: Option<Vec<String>>,
    /// Override the global `[pools] default_receivers` for this wallet.
    default_receivers: Option<Vec<String>>,
    /// Override the global `[pools] transparent` for this wallet.
    transparent: Option<bool>,
    /// Override the global `[pools] transparent_default` for this wallet.
    transparent_default: Option<bool>,
    /// Override the global `[pools] transparent_gap_limit` for this wallet.
    transparent_gap_limit: Option<u32>,
    /// Override the global `[pools] transparent_initial_scan` for this wallet.
    transparent_initial_scan: Option<u32>,
    /// Override the global `[pools] transparent_allow_beyond_recovery_window` for this wallet.
    transparent_allow_beyond_recovery_window: Option<bool>,
    /// Override the global `[pools] transparent_gap_warn_threshold` for this wallet.
    transparent_gap_warn_threshold: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendFile {
    server: Option<String>,
    connect_timeout_secs: Option<u64>,
    reconnect_base_secs: Option<u64>,
    reconnect_max_secs: Option<u64>,
    rfc1918_is_local: Option<bool>,
    allow_remote_cleartext: Option<bool>,
    /// lightwalletd TLS mode: `auto` (default) / `yes` / `no`.
    tls: Option<String>,
    /// lightwalletd TLS root store: `native` (default) / `webpki`.
    tls_roots: Option<String>,
    /// Accept any lightwalletd TLS certificate (default `false`). Unsafe - see
    /// [`BackendConfig::tls_insecure_skip_verify`].
    tls_insecure_skip_verify: Option<bool>,
    /// Path to a PEM bundle holding a private CA to trust for lightwalletd TLS.
    tls_ca_file: Option<PathBuf>,
    /// SHA-256 leaf-certificate fingerprints to pin lightwalletd TLS to (`openssl x509 -noout
    /// -fingerprint -sha256` form; colons optional, case-insensitive).
    tls_pinned_sha256: Option<Vec<String>>,
    /// Assert that the upstream lightwalletd serves transparent data in compact blocks - see
    /// [`BackendConfig::assume_transparent_in_compact_blocks`].
    assume_transparent_in_compact_blocks: Option<bool>,
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
    allow_duplicate_shielded_recipients: Option<bool>,
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
    pipeline_proving: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolsFile {
    enabled: Option<Vec<String>>,
    default_receivers: Option<Vec<String>>,
    /// Enable bare transparent (`t1…`/`tm…`) receiving addresses.
    transparent: Option<bool>,
    /// Make a bare transparent address the no-argument `getnewaddress` default (implies
    /// `transparent`).
    transparent_default: Option<bool>,
    /// External transparent gap limit (restore scan depth past the last funded address).
    transparent_gap_limit: Option<u32>,
    /// Initial transparent scan depth (pre-expose + scan indices `0..N` on startup/restore).
    transparent_initial_scan: Option<u32>,
    /// Allow `getnewaddress` to issue transparent addresses beyond the recovery window (warn-only).
    transparent_allow_beyond_recovery_window: Option<bool>,
    /// Warn when fewer than this many in-window transparent address slots remain.
    transparent_gap_warn_threshold: Option<u32>,
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// CLI-shaped overrides to configuration resolution, decoupled from clap so a library consumer
/// can resolve an [`AppConfig`] without the CLI surface. The fields mirror [`Cli`]'s global
/// flags one for one, and [`Cli`] converts into this, so the daemon and an embedder resolve
/// configuration identically.
///
/// NB the `ZECD_RPC_PASSWORD` / `ZECD_AGE_IDENTITY` / `ZECD_KEYS_FILE` env fallbacks are clap
/// behavior on the corresponding [`Cli`] flags and do NOT apply here - a library caller sets
/// the fields explicitly. `ZECD_DATADIR` still applies (it is resolved during resolution, not
/// by clap).
#[derive(Debug, Default, Clone)]
pub struct ConfigOverrides {
    /// Path to the TOML config file (default: `<datadir>/zecd.toml`).
    pub conf: Option<PathBuf>,
    /// Data directory holding per-wallet subdirectories and the cookie file.
    pub datadir: Option<PathBuf>,
    /// Use testnet (overrides config `network`).
    pub testnet: bool,
    /// Use regtest (overrides config `network`).
    pub regtest: bool,
    /// Network: "main", "test", or "regtest".
    pub network: Option<String>,
    /// RPC bind address.
    pub rpc_bind: Option<String>,
    /// RPC port.
    pub rpc_port: Option<u16>,
    /// RPC username (HTTP Basic auth).
    pub rpc_user: Option<String>,
    /// RPC password (HTTP Basic auth).
    pub rpc_password: Option<String>,
    /// rpcauth credentials (`<user>:<salt>$<hmac-sha256 hex>`).
    pub rpc_auth: Vec<String>,
    /// Chain upstream token (`zebra`, `zebra://host:port`, `zecrocks`, `https://...`, ...).
    pub server: Option<String>,
    /// age identity file used to decrypt the wallet seed for sending.
    pub age_identity: Option<PathBuf>,
    /// Path to the default wallet's `keys.toml`, independent of the datadir.
    pub keys_file: Option<PathBuf>,
}

#[cfg(feature = "cli")]
impl From<&Cli> for ConfigOverrides {
    fn from(cli: &Cli) -> ConfigOverrides {
        ConfigOverrides {
            conf: cli.conf.clone(),
            datadir: cli.datadir.clone(),
            testnet: cli.testnet,
            regtest: cli.regtest,
            network: cli.network.clone(),
            rpc_bind: cli.rpc_bind.clone(),
            rpc_port: cli.rpc_port,
            rpc_user: cli.rpc_user.clone(),
            rpc_password: cli.rpc_password.clone(),
            rpc_auth: cli.rpc_auth.clone(),
            server: cli.server.clone(),
            age_identity: cli.age_identity.clone(),
            keys_file: cli.keys_file.clone(),
        }
    }
}

/// `zecd` - a Bitcoin-Core-style JSON-RPC server for shielded-first Zcash.
// Every flag here is `global`, so it is accepted before *or* after a subcommand
// (`zecd --conf f config check` and `zecd config check --conf f` are the same command). That
// matters most for `config check`, whose whole job is resolving a named config the way the daemon
// would - having to remember that `--conf` only works in one position would be a trap on the one
// command an operator reaches for when something is already wrong. (A normal comment, not a doc
// comment: clap renders the doc comment as the command's help text, and this is a note for
// readers of the source.)
#[cfg(feature = "cli")]
#[derive(Debug, Parser)]
#[command(name = "zecd", version)]
pub struct Cli {
    /// Path to the TOML config file (default: <datadir>/zecd.toml, else ./zecd.toml).
    #[arg(long, global = true, value_name = "FILE")]
    pub conf: Option<PathBuf>,

    /// Data directory holding per-wallet subdirectories and the cookie file.
    #[arg(long, global = true, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// Use testnet (overrides config `network`).
    #[arg(long, global = true)]
    pub testnet: bool,

    /// Use regtest - a local zebra regtest chain (overrides config `network`).
    #[arg(long, global = true)]
    pub regtest: bool,

    /// Network: "main", "test", or "regtest".
    #[arg(long, global = true, value_name = "NET")]
    pub network: Option<String>,

    /// RPC bind address.
    #[arg(long = "rpcbind", global = true, value_name = "ADDR")]
    pub rpc_bind: Option<String>,

    /// RPC port.
    #[arg(long = "rpcport", global = true, value_name = "PORT")]
    pub rpc_port: Option<u16>,

    /// RPC username (HTTP Basic auth).
    #[arg(long = "rpcuser", global = true, value_name = "USER")]
    pub rpc_user: Option<String>,

    /// RPC password (HTTP Basic auth). May also be supplied via `ZECD_RPC_PASSWORD` or
    /// `[rpc] password_file` so it need not live in the (ConfigMap-bound) TOML.
    #[arg(
        long = "rpcpassword",
        global = true,
        value_name = "PASS",
        env = "ZECD_RPC_PASSWORD"
    )]
    pub rpc_password: Option<String>,

    /// rpcauth credential (`<user>:<salt>$<hmac-sha256 hex>`); may be repeated.
    #[arg(long = "rpcauth", global = true, value_name = "USER:SALT$HASH")]
    pub rpc_auth: Vec<String>,

    /// Chain upstream: `zebra` (local zebrad, the default) or `zebra://host:port`.
    #[arg(long, global = true, value_name = "SERVER")]
    pub server: Option<String>,

    /// age identity file used to decrypt the wallet seed for sending.
    #[arg(long, global = true, value_name = "FILE", env = "ZECD_AGE_IDENTITY")]
    pub age_identity: Option<PathBuf>,

    /// Path to the default wallet's `keys.toml`, independent of the datadir (so the encrypted
    /// seed can be a mounted Secret while the datadir stays a disposable cache).
    #[arg(long, global = true, value_name = "FILE", env = "ZECD_KEYS_FILE")]
    pub keys_file: Option<PathBuf>,

    /// Subcommand. When omitted, runs the daemon.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Create and initialize a new wallet (mnemonic + accounts), then exit.
    Init(InitArgs),
    /// Print a wallet's Unified Full Viewing Key (for pairing a watch-only instance via
    /// `init --ufvk`), then exit.
    ExportUfvk(ExportUfvkArgs),
    /// Derive receiving addresses offline - no chain, no wallet database, no daemon - from an
    /// initialized wallet's `keys.toml`, a BIP-39 mnemonic, or a Unified Full Viewing Key, then
    /// exit.
    DeriveAddress(DeriveAddressArgs),
    /// Generate a salted bitcoind-style `[rpc] auth` credential line (no external
    /// `rpcauth.py` needed), then exit.
    Rpcauth(RpcauthArgs),
    /// Print the annotated example configuration file to stdout (or `--output-file`), then
    /// exit. Redirect it to `<datadir>/zecd.toml` and edit to taste.
    ExampleConfig(ExampleConfigArgs),
    /// Inspect the configuration (`zecd config check`), then exit.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Rebuild a wallet whose database is broken: delete the wallet database (keys.toml and
    /// the seed are kept) so the next daemon start recreates the account from the seed and
    /// rescans the chain from the wallet birthday, re-deriving all funds and history. Refuses
    /// to run while the daemon holds the data directory.
    Rescan(RescanArgs),
    /// Run the JSON-RPC daemon (default).
    Run,
}

#[cfg(feature = "cli")]
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

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct RpcauthArgs {
    /// RPC username the credential is for.
    pub username: String,

    /// Password to hash. If omitted, a strong random password is generated and printed once.
    pub password: Option<String>,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct ExampleConfigArgs {
    /// Write the config here instead of stdout. `-` also means stdout. Refuses to overwrite an
    /// existing file unless `--force`.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output_file: Option<PathBuf>,

    /// Overwrite `--output-file` if it already exists.
    #[arg(long)]
    pub force: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Subcommand)]
pub enum ConfigCommand {
    /// Validate a configuration file against this zecd build without starting the daemon, and
    /// print the settings it resolves to. Exits non-zero if the daemon would refuse to start.
    Check(ConfigCheckArgs),
    /// Print the effective configuration - the file, CLI flags and environment resolved
    /// together, with every unset key filled in by this build's default - as TOML, then exit.
    Show(ConfigShowArgs),
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct ConfigCheckArgs {
    /// Treat warnings as errors, so a config that merely looks risky also exits non-zero
    /// (for CI gates on a deployment repository).
    #[arg(long)]
    pub strict: bool,

    /// Suppress the effective-configuration summary (stdout) and the success line; problems
    /// and the exit code are still reported on stderr.
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

/// `zecd config show` takes no options of its own - the configuration it renders is selected by
/// the global flags (`--conf`, `--datadir`, `--network`, ...), exactly as the daemon selects it.
#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct ConfigShowArgs {}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct ExportUfvkArgs {
    /// Wallet name (selects <datadir>/<name>).
    #[arg(long, default_value = "default")]
    pub wallet: String,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct DeriveAddressArgs {
    /// Wallet name (selects <datadir>/<name>). The default key source is this wallet's
    /// `keys.toml`; with `--mnemonic`/`--ufvk` the wallet is only consulted for its receiver
    /// configuration and to check the supplied key against its pinned viewing key. Omitted, the
    /// `default` wallet's configuration is used.
    #[arg(long)]
    pub wallet: Option<String>,

    /// Derive from a BIP-39 mnemonic instead of the wallet's `keys.toml`. The phrase is read
    /// from `ZECD_MNEMONIC`, else `--mnemonic-file`, else stdin.
    #[arg(long)]
    pub mnemonic: bool,

    /// Read the mnemonic phrase from this file (trailing newline trimmed) instead of stdin,
    /// for non-interactive derivation. Implies `--mnemonic`; `ZECD_MNEMONIC` takes precedence.
    #[arg(long, value_name = "FILE")]
    pub mnemonic_file: Option<PathBuf>,

    /// Derive from this Unified Full Viewing Key (see `export-ufvk`) instead of a mnemonic or
    /// the wallet's `keys.toml`. Addresses are the same either way - only spending needs a seed.
    #[arg(long, value_name = "UFVK", conflicts_with_all = ["mnemonic", "mnemonic_file"])]
    pub ufvk: Option<String>,

    /// Which receivers to derive, in `getnewaddress`'s `address_type` syntax: `unified`
    /// (alias `default`) for the wallet's configured receivers, `transparent` for a bare
    /// t-address, or a shielded pool list such as `orchard` / `sapling,orchard`. Defaults to
    /// what `getnewaddress` would hand out for this wallet.
    #[arg(long, value_name = "TYPE")]
    pub address_type: Option<String>,

    /// The first index to derive: a diversifier index for a Unified Address, or the BIP-44
    /// external child index for a bare transparent address (the same index the daemon exposes).
    #[arg(long, default_value_t = 0)]
    pub index: u64,

    /// How many consecutive indices to derive (one address per line), for pre-provisioning a
    /// batch of deposit addresses.
    #[arg(long, default_value_t = 1)]
    pub count: u32,

    /// Emit a JSON object instead of one address per line.
    #[arg(long)]
    pub json: bool,
}

#[cfg(feature = "cli")]
#[derive(Debug, clap::Args)]
pub struct RescanArgs {
    /// Wallet name (selects <datadir>/<name>).
    #[arg(long, default_value = "default")]
    pub wallet: String,

    /// Skip the interactive confirmation prompt (for non-interactive/automated recovery).
    #[arg(long)]
    pub yes: bool,
}

impl AppConfig {
    /// Resolve the effective configuration from CLI flags and the TOML file, using zecd's
    /// file/port defaults.
    #[cfg(feature = "cli")]
    pub fn resolve(cli: &Cli) -> anyhow::Result<AppConfig> {
        Self::resolve_with(cli, &ZECD_DEFAULTS)
    }

    /// Resolve the effective configuration from clap-free overrides and the TOML file, using
    /// zecd's file/port defaults - the library consumer's entry point ([`Cli`] converts into
    /// [`ConfigOverrides`], so this and [`resolve`](Self::resolve) cannot disagree).
    pub fn resolve_overrides(overrides: &ConfigOverrides) -> anyhow::Result<AppConfig> {
        Self::resolve_overrides_with(overrides, &ZECD_DEFAULTS)
    }

    /// The datadir named in the overrides (the command line) or in the environment, before the
    /// config file is read. The file is located *before* its own `datadir` can apply (like
    /// bitcoind: `-conf` resolution never depends on a datadir set inside the file), so the
    /// lookup uses only overrides/env. Datadir precedence overall: CLI > env (`ZECD_DATADIR`) >
    /// config file > default.
    fn cli_datadir(overrides: &ConfigOverrides, defaults: &BinaryDefaults) -> Option<PathBuf> {
        overrides
            .datadir
            .clone()
            .or_else(|| std::env::var_os(defaults.datadir_env).map(PathBuf::from))
    }

    /// The config file [`resolve`](Self::resolve) would read for this invocation, whether or not
    /// it exists. Exposed so `zecd config check` can name the file it is checking - and can only
    /// ever check the same one the daemon would load.
    #[cfg(feature = "cli")]
    pub fn conf_path(cli: &Cli) -> PathBuf {
        Self::conf_path_with(cli, &ZECD_DEFAULTS)
    }

    /// [`conf_path`](Self::conf_path) with the binary's defaults.
    #[cfg(feature = "cli")]
    pub fn conf_path_with(cli: &Cli, defaults: &BinaryDefaults) -> PathBuf {
        Self::conf_path_overrides_with(&ConfigOverrides::from(cli), defaults)
    }

    /// [`conf_path`](Self::conf_path) from clap-free overrides.
    pub fn conf_path_overrides_with(
        overrides: &ConfigOverrides,
        defaults: &BinaryDefaults,
    ) -> PathBuf {
        overrides.conf.clone().unwrap_or_else(|| {
            Self::cli_datadir(overrides, defaults)
                .unwrap_or_else(|| PathBuf::from(defaults.datadir))
                .join(defaults.conf_file)
        })
    }

    /// Resolve the effective configuration with the binary's defaults (`zecd`).
    #[cfg(feature = "cli")]
    pub fn resolve_with(cli: &Cli, defaults: &BinaryDefaults) -> anyhow::Result<AppConfig> {
        Self::resolve_overrides_with(&ConfigOverrides::from(cli), defaults)
    }

    /// [`resolve_overrides`](Self::resolve_overrides) with caller-supplied binary defaults.
    pub fn resolve_overrides_with(
        overrides: &ConfigOverrides,
        defaults: &BinaryDefaults,
    ) -> anyhow::Result<AppConfig> {
        // The overrides mirror the CLI flags one for one, so the body keeps its `cli` naming
        // (and its diff against the pre-overrides version stays a two-line header change).
        let cli = overrides;
        let cli_datadir = Self::cli_datadir(cli, defaults);
        let conf_path = Self::conf_path_overrides_with(cli, defaults);

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
            let keys_file = w.keys_file.clone().or_else(|| {
                if name == &default_wallet {
                    keys_file_global.clone()
                } else {
                    None
                }
            });
            let coin = Coin::Zcash;
            let dir = w.dir.clone().unwrap_or_else(|| wallet_dir(&datadir, name));
            let backend_override = resolve_wallet_backend(name, w)?;
            let (
                enabled,
                default_receivers,
                transparent_enabled,
                transparent_default,
                transparent_gap_limit,
                transparent_initial_scan,
                transparent_allow_beyond_recovery_window,
                transparent_gap_warn_threshold,
            ) = resolve_wallet_pools(
                name,
                w.pools.as_deref(),
                w.default_receivers.as_deref(),
                w.transparent,
                w.transparent_default,
                w.transparent_gap_limit,
                w.transparent_initial_scan,
                w.transparent_allow_beyond_recovery_window,
                w.transparent_gap_warn_threshold,
                &pools,
            )?;
            wallets.insert(
                name.clone(),
                WalletEntry {
                    dir,
                    keys_file,
                    coin,
                    chain: coin.chain(network),
                    backend: backend_override,
                    pools: enabled,
                    default_receivers,
                    transparent_enabled,
                    transparent_default,
                    transparent_gap_limit,
                    transparent_initial_scan,
                    transparent_allow_beyond_recovery_window,
                    transparent_gap_warn_threshold,
                },
            );
        }
        wallets
            .entry(default_wallet.clone())
            .or_insert_with(|| WalletEntry {
                dir: wallet_dir(&datadir, &default_wallet),
                keys_file: keys_file_global.clone(),
                coin: Coin::Zcash,
                chain: Coin::Zcash.chain(network),
                backend: WalletBackendOverride::default(),
                pools: pools.enabled.clone(),
                default_receivers: pools.default_receivers.clone(),
                transparent_enabled: pools.transparent_enabled,
                transparent_default: pools.transparent_default,
                transparent_gap_limit: pools.transparent_gap_limit,
                transparent_initial_scan: pools.transparent_initial_scan,
                transparent_allow_beyond_recovery_window: pools
                    .transparent_allow_beyond_recovery_window,
                transparent_gap_warn_threshold: pools.transparent_gap_warn_threshold,
            });

        let backend_file = file.backend.unwrap_or(BackendFile {
            server: None,
            connect_timeout_secs: None,
            reconnect_base_secs: None,
            reconnect_max_secs: None,
            rfc1918_is_local: None,
            allow_remote_cleartext: None,
            tls: None,
            tls_roots: None,
            tls_insecure_skip_verify: None,
            tls_ca_file: None,
            tls_pinned_sha256: None,
            assume_transparent_in_compact_blocks: None,
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
            rfc1918_is_local: backend_file.rfc1918_is_local.unwrap_or(true),
            allow_remote_cleartext: backend_file.allow_remote_cleartext.unwrap_or(false),
            tls: match backend_file.tls.as_deref() {
                Some(mode) => crate::backend::parse_tls_mode(mode).context("[backend] tls")?,
                None => None,
            },
            tls_roots: match backend_file.tls_roots.as_deref() {
                Some(roots) => {
                    crate::backend::TlsRoots::parse(roots).context("[backend] tls_roots")?
                }
                None => crate::backend::TlsRoots::default(),
            },
            tls_insecure_skip_verify: backend_file.tls_insecure_skip_verify.unwrap_or(false),
            // Read now, not at connect time: an unreadable or malformed CA file must fail
            // startup rather than leave the daemon quietly falling back to the public roots
            // (the same fail-fast rule `[rpc] password_file` follows).
            tls_ca_pem: match backend_file.tls_ca_file.as_deref() {
                Some(path) => Some(std::fs::read(path).with_context(|| {
                    format!("reading [backend] tls_ca_file {}", path.display())
                })?),
                None => None,
            },
            tls_ca_file: backend_file.tls_ca_file.clone(),
            tls_pins: backend_file
                .tls_pinned_sha256
                .unwrap_or_default()
                .iter()
                .map(|s| crate::backend::CertFingerprint::parse(s))
                .collect::<anyhow::Result<Vec<_>>>()
                .context("[backend] tls_pinned_sha256")?,
            assume_transparent_in_compact_blocks: backend_file
                .assume_transparent_in_compact_blocks
                .unwrap_or(false),
        };
        validate_backend_tls(&backend)?;
        // Same contradiction checks for every wallet that overrides the endpoint, against its
        // effective settings - a never-consulted pin is exactly as silent per wallet as it is
        // globally.
        for (name, entry) in &wallets {
            if !entry.backend.is_empty() {
                validate_backend_tls(&entry.backend.effective(&backend))
                    .with_context(|| format!("[wallets.{name}]"))?;
            }
        }

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
            allow_duplicate_shielded_recipients: None,
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
            allow_duplicate_shielded_recipients: rpc_file
                .allow_duplicate_shielded_recipients
                .unwrap_or(false),
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
            // Clamp to >= 1s so a misconfigured `interval_secs = 0` can't make the actor busy-poll
            // the backend with no idle delay between passes (same guard as `rebroadcast_secs`).
            interval_secs: sync_file.interval_secs.unwrap_or(20).max(1),
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
            pipeline_proving: spend_file.pipeline_proving.unwrap_or(false),
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
            // Default to "synced": `/readyz` reports ready only once the wallet has actually
            // scanned to (near) the tip, so a client routed by readiness never sees an empty or
            // stale balance/history as authoritative during initial sync or a `--restore` (audit
            // 3.15). Deployments that prefer reachability-over-freshness - reaching zecd while it
            // catches up, at the cost of possibly-lagging reads - can set `readiness = "connected"`.
            readiness: health_file
                .readiness
                .as_deref()
                .map(ReadinessMode::parse)
                .transpose()?
                .unwrap_or(ReadinessMode::Synced),
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
        // `init_tracing` treats anything that is not "json" as text, so a typo like "jsonl"
        // would silently produce text logs; refuse it here instead (and `config check`
        // reports the same refusal without starting anything).
        if !["text", "json"]
            .iter()
            .any(|v| log.format.eq_ignore_ascii_case(v))
        {
            anyhow::bail!(
                "[log] format must be \"text\" or \"json\", got {:?}",
                log.format
            );
        }

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

/// Refuse the shipped placeholder RPC password on mainnet, where the RPC credential is spend
/// authority. The example config and the deploy templates ship `change-me`/`CHANGE-ME`, so a
/// config that still carries it was never edited.
///
/// Deliberately *not* part of [`AppConfig::resolve`]: it is a startup policy, not a parse rule,
/// and `resolve` is used by tooling (`config check`) that must be able to describe such a config
/// rather than fail to build it. Both the daemon and `zecd config check` call this, so the two
/// always agree on the verdict.
pub fn reject_placeholder_password(config: &AppConfig) -> anyhow::Result<()> {
    if matches!(config.network, ZNetwork::Main)
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
    Ok(())
}

/// Resolve and validate the global `[pools]` section. `enabled` defaults to Orchard-only;
/// `default_receivers` defaults to the enabled set. The receivers must be a subset of the
/// enabled pools.
/// Reject `[backend]` TLS settings that contradict each other, at load rather than at connect.
///
/// The failure being prevented is a *silent* one: a pin or a private CA that is never consulted
/// looks in the config exactly like one that is, so an operator who believes the connection is
/// authenticated would have no signal that it isn't. Two shapes are caught here (the third, a
/// bare `host:port` that the locality heuristic resolves to plaintext, is caught at connect,
/// where the heuristic has run).
fn validate_backend_tls(backend: &BackendConfig) -> anyhow::Result<()> {
    let authenticating = backend.tls_ca_pem.is_some() || !backend.tls_pins.is_empty();
    if authenticating && backend.tls_insecure_skip_verify {
        anyhow::bail!(
            "[backend] tls_insecure_skip_verify = true cannot be combined with \
             tls_pinned_sha256/tls_ca_file: it disables the very check they configure. Remove \
             tls_insecure_skip_verify - a pin authenticates a self-signed certificate without \
             giving up verification"
        );
    }
    if authenticating && backend.tls == Some(false) {
        anyhow::bail!(
            "[backend] tls_pinned_sha256/tls_ca_file require TLS, but tls = \"no\" forces a \
             plaintext connection where neither can be checked"
        );
    }
    if authenticating && backend.server.starts_with("http://") {
        anyhow::bail!(
            "[backend] tls_pinned_sha256/tls_ca_file require TLS, but the http:// server token \
             forces a plaintext connection where neither can be checked; use https://"
        );
    }
    Ok(())
}

/// Parse a wallet's `[wallets.<name>]` backend override keys. Each key is parsed by the same
/// helper the global `[backend]` section uses, so the two cannot drift; errors name the exact
/// TOML key that is wrong.
fn resolve_wallet_backend(name: &str, w: &WalletFile) -> anyhow::Result<WalletBackendOverride> {
    Ok(WalletBackendOverride {
        server: w.server.clone(),
        tls: match w.tls.as_deref() {
            Some(mode) => Some(
                crate::backend::parse_tls_mode(mode)
                    .with_context(|| format!("[wallets.{name}] tls"))?,
            ),
            None => None,
        },
        tls_roots: match w.tls_roots.as_deref() {
            Some(roots) => Some(
                crate::backend::TlsRoots::parse(roots)
                    .with_context(|| format!("[wallets.{name}] tls_roots"))?,
            ),
            None => None,
        },
        tls_insecure_skip_verify: w.tls_insecure_skip_verify,
        // Read now, not at connect time, exactly as the global key is: an unreadable CA file
        // must fail startup rather than leave this wallet silently on the public roots.
        tls_ca_pem: match w.tls_ca_file.as_deref() {
            Some(path) => Some(std::fs::read(path).with_context(|| {
                format!("reading [wallets.{name}] tls_ca_file {}", path.display())
            })?),
            None => None,
        },
        tls_ca_file: w.tls_ca_file.clone(),
        tls_pins: match &w.tls_pinned_sha256 {
            Some(pins) => Some(
                pins.iter()
                    .map(|s| crate::backend::CertFingerprint::parse(s))
                    .collect::<anyhow::Result<Vec<_>>>()
                    .with_context(|| format!("[wallets.{name}] tls_pinned_sha256"))?,
            ),
            None => None,
        },
        assume_transparent_in_compact_blocks: w.assume_transparent_in_compact_blocks,
    })
}

fn resolve_global_pools(file: Option<&PoolsFile>) -> anyhow::Result<PoolsConfig> {
    let enabled = match file.and_then(|f| f.enabled.as_deref()) {
        Some(tokens) => ReceiverSet::parse(tokens).context("[pools] enabled")?,
        None => ReceiverSet::single(Receiver::Orchard),
    };
    let default_receivers = match file.and_then(|f| f.default_receivers.as_deref()) {
        Some(tokens) => ReceiverSet::parse(tokens).context("[pools] default_receivers")?,
        None => enabled.clone(),
    };
    if !default_receivers.is_subset_of(&enabled) {
        anyhow::bail!(
            "[pools] default_receivers ({}) must be a subset of enabled pools ({})",
            default_receivers.display_names(),
            enabled.display_names()
        );
    }
    let transparent_enabled = file.and_then(|f| f.transparent).unwrap_or(false);
    let transparent_default = file.and_then(|f| f.transparent_default).unwrap_or(false);
    let transparent_gap_limit = file
        .and_then(|f| f.transparent_gap_limit)
        .unwrap_or(DEFAULT_TRANSPARENT_GAP_LIMIT);
    let transparent_initial_scan = file.and_then(|f| f.transparent_initial_scan).unwrap_or(0);
    let transparent_allow_beyond_recovery_window = file
        .and_then(|f| f.transparent_allow_beyond_recovery_window)
        .unwrap_or(DEFAULT_TRANSPARENT_ALLOW_BEYOND);
    let transparent_gap_warn_threshold = file
        .and_then(|f| f.transparent_gap_warn_threshold)
        .unwrap_or(DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD);
    validate_transparent_flags(
        "[pools]",
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
    )?;
    Ok(PoolsConfig {
        enabled,
        default_receivers,
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
        transparent_initial_scan,
        transparent_allow_beyond_recovery_window,
        transparent_gap_warn_threshold,
    })
}

/// `transparent_default` makes a bare t-address the no-argument `getnewaddress` default, so it
/// only makes sense when transparent receiving is enabled at all. The gap limit must be at least 1
/// (0 would scan no addresses and recover nothing on restore). There is deliberately no upper
/// bound here: a very wide window is an operator's (costly) choice, warned about loudly at actor
/// spawn ([`TRANSPARENT_GAP_LIMIT_COSTLY`] / [`TRANSPARENT_GAP_LIMIT_SEVERE`]) rather than
/// rejected.
fn validate_transparent_flags(
    ctx: &str,
    transparent_enabled: bool,
    transparent_default: bool,
    transparent_gap_limit: u32,
) -> anyhow::Result<()> {
    if transparent_default && !transparent_enabled {
        anyhow::bail!(
            "{ctx} transparent_default = true requires transparent = true \
             (transparent receiving must be enabled to default to it)"
        );
    }
    if transparent_gap_limit == 0 {
        anyhow::bail!("{ctx} transparent_gap_limit must be at least 1");
    }
    Ok(())
}

/// Resolve and validate one wallet's pools/receivers against the global defaults. A wallet that
/// overrides `pools` but not `default_receivers` receives into all of its enabled pools by
/// default; a wallet that overrides neither inherits the global defaults.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn resolve_wallet_pools(
    name: &str,
    pools: Option<&[String]>,
    default_receivers: Option<&[String]>,
    transparent: Option<bool>,
    transparent_default: Option<bool>,
    transparent_gap_limit: Option<u32>,
    transparent_initial_scan: Option<u32>,
    transparent_allow_beyond_recovery_window: Option<bool>,
    transparent_gap_warn_threshold: Option<u32>,
    global: &PoolsConfig,
) -> anyhow::Result<(ReceiverSet, ReceiverSet, bool, bool, u32, u32, bool, u32)> {
    let enabled = match pools {
        Some(tokens) => {
            ReceiverSet::parse(tokens).with_context(|| format!("[wallets.{name}] pools"))?
        }
        None => global.enabled.clone(),
    };
    let receivers = match (default_receivers, pools) {
        (Some(tokens), _) => ReceiverSet::parse(tokens)
            .with_context(|| format!("[wallets.{name}] default_receivers"))?,
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
    // Per-wallet transparent flags fall back to the global values when not overridden.
    let transparent_enabled = transparent.unwrap_or(global.transparent_enabled);
    let transparent_default = transparent_default.unwrap_or(global.transparent_default);
    let transparent_gap_limit = transparent_gap_limit.unwrap_or(global.transparent_gap_limit);
    let transparent_initial_scan =
        transparent_initial_scan.unwrap_or(global.transparent_initial_scan);
    let transparent_allow_beyond_recovery_window = transparent_allow_beyond_recovery_window
        .unwrap_or(global.transparent_allow_beyond_recovery_window);
    let transparent_gap_warn_threshold =
        transparent_gap_warn_threshold.unwrap_or(global.transparent_gap_warn_threshold);
    validate_transparent_flags(
        &format!("[wallets.{name}]"),
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
    )?;
    Ok((
        enabled,
        receivers,
        transparent_enabled,
        transparent_default,
        transparent_gap_limit,
        transparent_initial_scan,
        transparent_allow_beyond_recovery_window,
        transparent_gap_warn_threshold,
    ))
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
        assert!(p.enabled.contains(Receiver::Orchard));
        assert!(!p.enabled.contains(Receiver::Sapling));
        assert_eq!(p.default_receivers, p.enabled);
    }

    #[test]
    fn global_default_receivers_default_to_enabled() {
        let f = PoolsFile {
            enabled: Some(s(&["sapling", "orchard"])),
            default_receivers: None,
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(p.enabled.contains(Receiver::Sapling) && p.enabled.contains(Receiver::Orchard));
        // Receivers fall back to the full enabled set.
        assert_eq!(p.default_receivers, p.enabled);
    }

    #[test]
    fn global_receivers_must_be_subset_of_enabled() {
        let f = PoolsFile {
            enabled: Some(s(&["orchard"])),
            default_receivers: Some(s(&["sapling"])),
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };
        assert!(resolve_global_pools(Some(&f)).is_err());
    }

    #[test]
    fn wallet_inherits_global_when_unset() {
        let global = PoolsConfig {
            enabled: ReceiverSet::parse(&s(&["sapling", "orchard"])).unwrap(),
            default_receivers: ReceiverSet::single(Receiver::Orchard),
            transparent_enabled: false,
            transparent_default: false,
            transparent_gap_limit: DEFAULT_TRANSPARENT_GAP_LIMIT,
            transparent_initial_scan: 0,
            transparent_allow_beyond_recovery_window: DEFAULT_TRANSPARENT_ALLOW_BEYOND,
            transparent_gap_warn_threshold: DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD,
        };
        let (enabled, receivers, _, _, _, _, _, _) =
            resolve_wallet_pools("w", None, None, None, None, None, None, None, None, &global)
                .unwrap();
        assert_eq!(enabled, global.enabled);
        assert_eq!(receivers, global.default_receivers);
    }

    #[test]
    fn wallet_overriding_pools_defaults_receivers_to_its_enabled() {
        // A wallet that narrows its pools but doesn't set receivers must not inherit the global
        // receivers (which could name a now-disabled pool) - it receives into all it enabled.
        let global = PoolsConfig::default(); // orchard-only
        let (enabled, receivers, _, _, _, _, _, _) = resolve_wallet_pools(
            "w",
            Some(&s(&["sapling"])),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &global,
        )
        .unwrap();
        assert!(enabled.contains(Receiver::Sapling) && !enabled.contains(Receiver::Orchard));
        assert_eq!(receivers, enabled);
    }

    #[test]
    fn wallet_receivers_not_subset_of_enabled_is_rejected() {
        let global = PoolsConfig::default();
        let err = resolve_wallet_pools(
            "hot",
            Some(&s(&["orchard"])),
            Some(&s(&["sapling"])),
            None,
            None,
            None,
            None,
            None,
            None,
            &global,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("wallets.hot"), "{err}");
        assert!(err.contains("subset"), "{err}");
    }

    #[test]
    fn transparent_flags_and_gap_limit() {
        // Default: transparent off, gap limit at the zecd default.
        let p = resolve_global_pools(None).unwrap();
        assert!(!p.transparent_enabled);
        assert!(!p.transparent_default);
        assert_eq!(p.transparent_gap_limit, DEFAULT_TRANSPARENT_GAP_LIMIT);

        // Explicit enable + custom gap limit are honored.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(50),
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(p.transparent_enabled);
        assert_eq!(p.transparent_gap_limit, 50);
        assert_eq!(p.transparent_initial_scan, 0, "initial scan defaults off");

        // Initial scan depth is independent of the gap limit.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(20),
            transparent_initial_scan: Some(10_000),
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert_eq!(p.transparent_gap_limit, 20);
        assert_eq!(p.transparent_initial_scan, 10_000);

        // A zero gap limit is rejected (would recover nothing on restore).
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(0),
            ..Default::default()
        };
        assert!(resolve_global_pools(Some(&f)).is_err());

        // A pathologically wide gap limit is rejected with guidance toward the A18 knob:
        // recording each transparent receive re-derives the whole window, so a huge window
        // stalls restores (the 0.5.1-rc2 field report ran transparent_gap_limit = 71000), but
        // the width is the operator's choice: it parses fine and is warned about at actor spawn
        // (error-level above TRANSPARENT_GAP_LIMIT_SEVERE), never rejected.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_gap_limit: Some(71_000),
            ..Default::default()
        };
        assert_eq!(
            resolve_global_pools(Some(&f))
                .unwrap()
                .transparent_gap_limit,
            71_000
        );

        // transparent_default without transparent is rejected.
        let f = PoolsFile {
            transparent_default: Some(true),
            ..Default::default()
        };
        let err = resolve_global_pools(Some(&f)).unwrap_err().to_string();
        assert!(err.contains("transparent"), "{err}");

        // Recovery-window knobs default to permissive + the standard warn threshold.
        let p = resolve_global_pools(None).unwrap();
        assert!(p.transparent_allow_beyond_recovery_window);
        assert_eq!(
            p.transparent_gap_warn_threshold,
            DEFAULT_TRANSPARENT_GAP_WARN_THRESHOLD
        );
        // ...and parse from `[pools]`.
        let f = PoolsFile {
            transparent: Some(true),
            transparent_allow_beyond_recovery_window: Some(false),
            transparent_gap_warn_threshold: Some(3),
            ..Default::default()
        };
        let p = resolve_global_pools(Some(&f)).unwrap();
        assert!(!p.transparent_allow_beyond_recovery_window);
        assert_eq!(p.transparent_gap_warn_threshold, 3);

        // Per-wallet override of the flags + gap limit + initial scan depth + recovery-window knobs.
        let global = PoolsConfig::default();
        let (_, _, te, td, gap, init, allow_beyond, warn_thresh) = resolve_wallet_pools(
            "w",
            None,
            None,
            Some(true),
            None,
            Some(7),
            Some(500),
            Some(false),
            Some(2),
            &global,
        )
        .unwrap();
        assert!(te && !td);
        assert_eq!(gap, 7);
        assert_eq!(init, 500, "per-wallet transparent_initial_scan override");
        assert!(
            !allow_beyond,
            "per-wallet transparent_allow_beyond_recovery_window override"
        );
        assert_eq!(
            warn_thresh, 2,
            "per-wallet transparent_gap_warn_threshold override"
        );

        // Per-wallet knobs inherit the global values when unset.
        let global = PoolsConfig {
            transparent_allow_beyond_recovery_window: false,
            transparent_gap_warn_threshold: 9,
            ..PoolsConfig::default()
        };
        let (_, _, _, _, _, _, allow_beyond, warn_thresh) =
            resolve_wallet_pools("w", None, None, None, None, None, None, None, None, &global)
                .unwrap();
        assert!(!allow_beyond, "inherits global allow_beyond");
        assert_eq!(warn_thresh, 9, "inherits global warn threshold");

        // A very wide per-wallet gap-limit override is likewise accepted (warned about at spawn,
        // not rejected); only 0 is invalid.
        let global = PoolsConfig::default();
        let (_, _, _, _, gap, _, _, _) = resolve_wallet_pools(
            "w",
            None,
            None,
            Some(true),
            None,
            Some(TRANSPARENT_GAP_LIMIT_SEVERE + 1),
            None,
            None,
            None,
            &global,
        )
        .unwrap();
        assert_eq!(gap, TRANSPARENT_GAP_LIMIT_SEVERE + 1);
        let err = resolve_wallet_pools(
            "w",
            None,
            None,
            Some(true),
            None,
            Some(0),
            None,
            None,
            None,
            &global,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("at least 1"), "{err}");
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
        // Absent -> the Zallet-matching default of 50.
        assert_eq!(SpendConfig::default().orchard_action_limit, 50);
        assert_eq!(DEFAULT_ORCHARD_ACTION_LIMIT, 50);
        // Explicit value (including 0, which disables the cap) round-trips.
        let f: SpendFile = toml::from_str("orchard_action_limit = 200").unwrap();
        assert_eq!(f.orchard_action_limit, Some(200));
        let f: SpendFile = toml::from_str("orchard_action_limit = 0").unwrap();
        assert_eq!(f.orchard_action_limit, Some(0));
    }

    #[test]
    fn pipeline_proving_defaults_off_and_parses() {
        // Absent -> off (the inline send path, byte-identical to today's behaviour).
        assert!(!SpendConfig::default().pipeline_proving);
        // Explicit value round-trips both ways.
        let f: SpendFile = toml::from_str("pipeline_proving = true").unwrap();
        assert_eq!(f.pipeline_proving, Some(true));
        let f: SpendFile = toml::from_str("pipeline_proving = false").unwrap();
        assert_eq!(f.pipeline_proving, Some(false));
    }

    #[test]
    fn privacy_policy_parses_known_values_only() {
        assert_eq!(
            SendPrivacy::parse("FullPrivacy").unwrap(),
            SendPrivacy::FullPrivacy
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedAmounts").unwrap(),
            SendPrivacy::AllowRevealedAmounts
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedRecipients").unwrap(),
            SendPrivacy::AllowRevealedRecipients
        );
        assert_eq!(
            SendPrivacy::parse("AllowRevealedSenders").unwrap(),
            SendPrivacy::AllowRevealedSenders
        );
        assert_eq!(
            SendPrivacy::parse("AllowFullyTransparent").unwrap(),
            SendPrivacy::AllowFullyTransparent
        );
        // Unknown values, and the `z_sendmany`-only `NoPrivacy` alias (which maps to
        // AllowFullyTransparent at the RPC layer but is not a canonical config token), are a
        // startup error, never a silent default.
        assert!(SendPrivacy::parse("NoPrivacy").is_err());
        assert!(SendPrivacy::parse("AllowLinkingAccountAddresses").is_err());
        assert!(SendPrivacy::parse("fullprivacy").is_err());
    }

    #[test]
    fn allows_transparent_recipient_ladder() {
        // The three upper rungs permit a transparent recipient; the two private rungs reject it.
        // Regression guard: `AllowFullyTransparent` (top rung) must be included, or `build_payment`
        // rejects the very t->t sends the policy exists to allow.
        assert!(!SendPrivacy::FullPrivacy.allows_transparent_recipient());
        assert!(!SendPrivacy::AllowRevealedAmounts.allows_transparent_recipient());
        assert!(SendPrivacy::AllowRevealedRecipients.allows_transparent_recipient());
        assert!(SendPrivacy::AllowRevealedSenders.allows_transparent_recipient());
        assert!(SendPrivacy::AllowFullyTransparent.allows_transparent_recipient());
    }

    #[test]
    fn allows_transparent_inputs_ladder() {
        // Only the two top rungs permit funding a send from transparent UTXOs (revealing the
        // sender). The default (`AllowRevealedRecipients`) must stay false: spending transparent
        // inputs is strictly opt-in via config or a per-call `privacyPolicy`.
        assert!(!SendPrivacy::FullPrivacy.allows_transparent_inputs());
        assert!(!SendPrivacy::AllowRevealedAmounts.allows_transparent_inputs());
        assert!(!SendPrivacy::AllowRevealedRecipients.allows_transparent_inputs());
        assert!(SendPrivacy::AllowRevealedSenders.allows_transparent_inputs());
        assert!(SendPrivacy::AllowFullyTransparent.allows_transparent_inputs());
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
        // The cleartext-gate knobs default to unset (-> rfc1918_is_local true, remote override
        // false) and parse when present.
        assert_eq!(f.rfc1918_is_local, None);
        assert_eq!(f.allow_remote_cleartext, None);
        let f: BackendFile =
            toml::from_str("rfc1918_is_local = false\nallow_remote_cleartext = true").unwrap();
        assert_eq!(f.rfc1918_is_local, Some(false));
        assert_eq!(f.allow_remote_cleartext, Some(true));
    }

    #[test]
    fn backend_file_parses_transparent_capability_override() {
        // Absent by default - asserting a capability the server does not advertise has to be a
        // deliberate act, since guessing wrong loses transparent receives silently.
        let f: BackendFile = toml::from_str("server = \"zecrocks\"").unwrap();
        assert_eq!(f.assume_transparent_in_compact_blocks, None);
        let f: BackendFile = toml::from_str("assume_transparent_in_compact_blocks = true").unwrap();
        assert_eq!(f.assume_transparent_in_compact_blocks, Some(true));
    }

    #[test]
    fn backend_file_parses_tls_options() {
        // Unset is the safe default: verification stays on, with no private CA and no pins.
        let f: BackendFile = toml::from_str("tls = \"yes\"\ntls_roots = \"webpki\"").unwrap();
        assert_eq!(f.tls.as_deref(), Some("yes"));
        assert_eq!(f.tls_roots.as_deref(), Some("webpki"));
        assert_eq!(f.tls_insecure_skip_verify, None);
        assert_eq!(f.tls_ca_file, None);
        assert_eq!(f.tls_pinned_sha256, None);
        // …and each of the three trust knobs has to be asked for explicitly.
        let f: BackendFile = toml::from_str("tls_insecure_skip_verify = true").unwrap();
        assert_eq!(f.tls_insecure_skip_verify, Some(true));
        let f: BackendFile = toml::from_str(
            "tls_ca_file = \"/etc/zecd/ca.pem\"\ntls_pinned_sha256 = [\"AB:CD\", \"ef01\"]",
        )
        .unwrap();
        assert_eq!(f.tls_ca_file, Some(PathBuf::from("/etc/zecd/ca.pem")));
        assert_eq!(
            f.tls_pinned_sha256,
            Some(vec!["AB:CD".to_string(), "ef01".to_string()])
        );
    }

    /// A `BackendConfig` with everything at its default, for the TLS-combination checks.
    fn backend_cfg() -> BackendConfig {
        BackendConfig {
            server: "zecrocks".into(),
            connect_timeout_secs: 10,
            reconnect_base_secs: 1,
            reconnect_max_secs: 60,
            rfc1918_is_local: true,
            allow_remote_cleartext: false,
            tls: None,
            tls_roots: Default::default(),
            tls_insecure_skip_verify: false,
            tls_ca_pem: None,
            tls_ca_file: None,
            tls_pins: Vec::new(),
            assume_transparent_in_compact_blocks: false,
        }
    }

    #[test]
    fn tls_trust_settings_compose_and_contradictions_are_rejected() {
        let pin = crate::backend::CertFingerprint::parse(&"ab".repeat(32)).unwrap();

        // Each knob alone is fine, and so is the pin + private-CA combination (pin the leaf,
        // validate the chain) - "optional everywhere" is the point of these settings.
        for cfg in [
            backend_cfg(),
            BackendConfig {
                tls_insecure_skip_verify: true,
                ..backend_cfg()
            },
            BackendConfig {
                tls_ca_pem: Some(b"pem".to_vec()),
                ..backend_cfg()
            },
            BackendConfig {
                tls_pins: vec![pin],
                ..backend_cfg()
            },
            BackendConfig {
                tls_ca_pem: Some(b"pem".to_vec()),
                tls_pins: vec![pin],
                ..backend_cfg()
            },
        ] {
            assert!(validate_backend_tls(&cfg).is_ok());
        }

        // Skipping verification cannot be combined with settings whose whole purpose is to
        // verify - that config would look authenticated while being anything but.
        let err = validate_backend_tls(&BackendConfig {
            tls_insecure_skip_verify: true,
            tls_pins: vec![pin],
            ..backend_cfg()
        })
        .unwrap_err();
        assert!(err.to_string().contains("tls_insecure_skip_verify"));

        // Nor can they ride a connection that will not be TLS at all, whether that is forced by
        // `tls = "no"`…
        assert!(validate_backend_tls(&BackendConfig {
            tls: Some(false),
            tls_pins: vec![pin],
            ..backend_cfg()
        })
        .is_err());
        // …or by an http:// endpoint.
        assert!(validate_backend_tls(&BackendConfig {
            server: "http://lwd.example.com:9067".into(),
            tls_ca_pem: Some(b"pem".to_vec()),
            ..backend_cfg()
        })
        .is_err());
        // A plaintext endpoint with no trust settings stays valid - that is the regtest harness.
        assert!(validate_backend_tls(&BackendConfig {
            server: "http://127.0.0.1:9067".into(),
            ..backend_cfg()
        })
        .is_ok());
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

    #[cfg(feature = "cli")]
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

    #[cfg(feature = "cli")]
    #[test]
    fn cleartext_gate_defaults_and_overrides_resolve() {
        use clap::Parser as _;
        // Security-critical defaults: an absent [backend] resolves to rfc1918_is_local = true
        // (private/LAN self-hosting works) and allow_remote_cleartext = false (no public leak).
        let cli = Cli::parse_from(["zecd"]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(cfg.backend.rfc1918_is_local);
        assert!(!cfg.backend.allow_remote_cleartext);

        // Both knobs are honored from the file.
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            "[backend]\nrfc1918_is_local = false\nallow_remote_cleartext = true\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert!(!cfg.backend.rfc1918_is_local);
        assert!(cfg.backend.allow_remote_cleartext);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn readiness_defaults_to_synced_and_is_overridable() {
        use clap::Parser as _;
        // Absent [health] readiness resolves to Synced: `/readyz` waits for the scan so a client
        // routed by readiness never trusts an empty/stale balance mid-sync.
        let cli = Cli::parse_from(["zecd"]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Synced);

        // A [health] block that omits `readiness` still defaults to Synced...
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(&conf, "[health]\nport = 9999\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Synced);

        // ...and the lenient mode is still opt-in from the file.
        std::fs::write(&conf, "[health]\nreadiness = \"connected\"\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.health.readiness, ReadinessMode::Connected);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn sync_interval_secs_is_clamped_to_at_least_one() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        // A misconfigured `interval_secs = 0` must not make the actor busy-poll with no idle
        // delay; it clamps up to 1s (mirroring `rebroadcast_secs`).
        std::fs::write(&conf, "[sync]\ninterval_secs = 0\nrebroadcast_secs = 0\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.sync.interval_secs, 1);
        assert_eq!(cfg.sync.rebroadcast_secs, 1);

        // An explicit larger value is preserved unchanged.
        std::fs::write(&conf, "[sync]\ninterval_secs = 45\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.sync.interval_secs, 45);

        // Absent section -> the 20s default.
        std::fs::write(&conf, "datadir = \"/tmp/zecd-x\"\n").unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.sync.interval_secs, 20);
    }

    /// The duplicate-shielded-recipient opt-in defaults off (zcashd parity is the default
    /// behaviour, not something an operator has to ask for) and parses both ways.
    #[cfg(feature = "cli")]
    #[test]
    fn allow_duplicate_shielded_recipients_defaults_off_and_parses() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        for (body, want) in [
            ("network = \"test\"\n", false),
            (
                "[rpc]\nallow_duplicate_shielded_recipients = false\n",
                false,
            ),
            ("[rpc]\nallow_duplicate_shielded_recipients = true\n", true),
        ] {
            std::fs::write(&conf, body).unwrap();
            let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            assert_eq!(
                cfg.rpc.allow_duplicate_shielded_recipients, want,
                "for config: {body}"
            );
        }
    }

    #[cfg(feature = "cli")]
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

    #[cfg(feature = "cli")]
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

    #[cfg(feature = "cli")]
    #[test]
    fn keys_file_override_resolves_per_wallet() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        // Default: keys.toml lives at the root of the wallet's dir, above the per-coin
        // subdirectories (see `Coin::data_dir`) - the seed it wraps serves every coin.
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
    #[cfg(feature = "cli")]
    fn every_resolved_wallet_is_a_zcash_wallet() {
        // The implicit default wallet and any named wallet alike. Nothing in the config file
        // selects this - it is a property of the build, resolved once so the rest of the tree
        // reads it from the entry rather than assuming it.
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.other]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();
        assert_eq!(cfg.wallets["default"].coin, Coin::Zcash);
        assert_eq!(cfg.wallets["other"].coin, Coin::Zcash);
    }

    #[test]
    #[cfg(feature = "cli")]
    fn wallet_chain_is_derived_from_the_daemon_environment() {
        // One environment per daemon: a wallet's chain follows from it rather than being
        // configured on its own, so there is no way to express a mainnet wallet in a testnet
        // daemon.
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(&conf, "datadir = \"/d\"\n[wallets.other]\n").unwrap();

        for (flag, env) in [("test", ZNetwork::Test), ("main", ZNetwork::Main)] {
            let cli = Cli::parse_from([
                "zecd",
                "--conf",
                conf.to_str().unwrap(),
                "--network",
                flag,
                "--rpcpassword",
                "not-the-placeholder",
            ]);
            let cfg = AppConfig::resolve(&cli).unwrap();
            for name in ["default", "other"] {
                let entry = &cfg.wallets[name];
                assert_eq!(entry.chain, CoinNetwork::Zcash(env));
                assert_eq!(entry.zcash_network(), env);
                assert_eq!(entry.zcash_network(), cfg.network);
            }
        }
    }

    #[test]
    #[cfg(feature = "cli")]
    fn per_wallet_backend_overrides_fall_back_to_the_global_section() {
        // One daemon, two upstreams: a zebra-backed wallet alongside a lightwalletd-backed one.
        // A wallet that overrides nothing must resolve exactly as it did before the keys existed.
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n\
             [backend]\nserver = \"zebra://127.0.0.1:18234\"\ntls_roots = \"webpki\"\n\
             [wallets.default]\n\
             [wallets.replica]\nserver = \"https://lwd.example:9067\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let cfg = AppConfig::resolve(&cli).unwrap();

        // No overrides: the global endpoint, unchanged.
        let default = &cfg.wallets["default"];
        assert!(default.backend.is_empty());
        let resolved = crate::backend::resolve_for_wallet(&cfg, default).unwrap();
        assert_eq!(
            resolved.describe(),
            crate::backend::resolve_configured(&cfg).unwrap().describe()
        );

        // Overridden server, but the global TLS settings still apply field by field.
        let replica = &cfg.wallets["replica"];
        assert!(!replica.backend.is_empty());
        let resolved = crate::backend::resolve_for_wallet(&cfg, replica).unwrap();
        assert_eq!(resolved.kind(), crate::backend::ServerKind::Lightwalletd);
        assert_eq!(
            replica.backend.effective(&cfg.backend).tls_roots,
            crate::backend::TlsRoots::Webpki
        );
    }

    #[test]
    #[cfg(feature = "cli")]
    fn per_wallet_backend_keys_are_parsed_and_validated_by_their_own_key() {
        use clap::Parser as _;
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("zecd.toml");

        // A bad value names the wallet's own key, not `[backend]`.
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n[wallets.a]\ntls_roots = \"bogus\"\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        let err = format!("{:#}", AppConfig::resolve(&cli).unwrap_err());
        assert!(err.contains("[wallets.a] tls_roots"), "{err}");

        // The TLS contradiction checks apply per wallet, against its effective settings.
        std::fs::write(
            &conf,
            "network = \"test\"\ndatadir = \"/d\"\n\
             [wallets.a]\nserver = \"https://lwd.example\"\ntls = \"no\"\n\
             tls_pinned_sha256 = [\"AA:BB\"]\n",
        )
        .unwrap();
        let cli = Cli::parse_from(["zecd", "--conf", conf.to_str().unwrap()]);
        assert!(AppConfig::resolve(&cli).is_err());
    }

    #[test]
    fn shipped_configs_parse() {
        // The example and docker configs must deserialize (deny_unknown_fields catches typos and
        // drift as the schema evolves).
        toml::from_str::<ConfigFile>(include_str!("../zecd.example.toml"))
            .expect("zecd.example.toml");
        // What `zecd example-config` emits must be loadable by the same binary that emitted it.
        toml::from_str::<ConfigFile>(crate::example_config::EXAMPLE_CONFIG)
            .expect("example-config output");
        toml::from_str::<ConfigFile>(include_str!("../deploy/zecd.toml"))
            .expect("deploy/zecd.toml");
        toml::from_str::<ConfigFile>(include_str!("../deploy/zecd.mainnet.toml"))
            .expect("deploy/zecd.mainnet.toml");
    }
}
