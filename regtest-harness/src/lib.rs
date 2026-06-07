//! End-to-end regtest harness for `zecd`.
//!
//! Orchestrates the **Zcash Foundation** regtest stack directly - `zebrad` (Regtest, PoW
//! disabled) + `lightwalletd` - and drives the real `zecd` daemon over its Bitcoin-Core-style
//! JSON-RPC. There is intentionally **no `zingo-infra`/`zcash_local_net` dependency**: we mine the
//! way zebra's own tests do (`getblocktemplate` → [`proposal_block_from_template`] → `submitblock`,
//! which needs no proof-of-work on Regtest), so the harness tracks *current* zebra and builds on
//! stable Rust.
//!
//! Binaries are supplied by the caller via `$ZEBRAD_BIN` / `$LIGHTWALLETD_BIN` (see
//! [`resolve_bin`]); in CI they're extracted from the official `zfnd/zebra` and
//! `electriccoinco/lightwalletd` images. `zecd` itself is the built release binary.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use zebra_chain::{
    parameters::{testnet::ConfiguredActivationHeights, Network},
    serialization::ZcashSerialize,
};
use zebra_rpc::{
    client::{BlockTemplateResponse, BlockTemplateTimeSource},
    proposal_block_from_template,
};

/// Pick an unused loopback TCP port (bind `:0`, read the port, release it). Racy by nature, but
/// fine for a single-threaded test run.
pub fn pick_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Resolve a required external binary from `$<env_var>`, returning `None` if unset or missing so
/// callers can skip the live test cleanly.
pub fn resolve_bin(env_var: &str) -> Option<PathBuf> {
    std::env::var(env_var).ok().map(PathBuf::from).filter(|p| p.is_file())
}

// =============================== zebrad (Regtest validator) ===============================

/// The `zebra-chain` Regtest network matching the zebrad config we write below: every upgrade
/// active from height 1 (NU5/Orchard included), the same convention as `zecd`'s `network::regtest`.
/// Used by [`proposal_block_from_template`] to pick the right block-commitment field.
fn regtest_network() -> Network {
    Network::new_regtest(
        ConfiguredActivationHeights { nu5: Some(1), nu6: Some(1), ..Default::default() }.into(),
    )
}

/// A running `zebrad` Regtest node.
pub struct Zebrad {
    child: Child,
    /// JSON-RPC port (cookie auth disabled so lightwalletd can connect).
    pub rpc_port: u16,
    net: Network,
    _dir: tempfile::TempDir,
}

impl Zebrad {
    /// Launch `zebrad` in Regtest mode and wait until its JSON-RPC answers.
    pub async fn start(bin: &Path) -> Result<Zebrad> {
        let dir = tempfile::tempdir().context("create zebrad dir")?;
        let rpc_port = pick_port()?;
        let net_port = pick_port()?;
        let config_path = dir.path().join("zebrad.toml");
        std::fs::write(&config_path, zebrad_toml(net_port, rpc_port)).context("write zebrad.toml")?;

        let child = Command::new(bin)
            .args(["--config", config_path.to_str().unwrap(), "start"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn zebrad ({})", bin.display()))?;

        let zebrad = Zebrad { child, rpc_port, net: regtest_network(), _dir: dir };
        zebrad.wait_until_rpc_up().await?;
        Ok(zebrad)
    }

    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.rpc_port)
    }

    async fn wait_until_rpc_up(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if zebra_rpc_call(&self.rpc_url(), "getblockchaininfo", json!([])).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("zebrad RPC did not come up within 90s");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Mine `n` blocks the way zebra's own regtest test does: fetch a template, assemble the block
    /// with [`proposal_block_from_template`], and submit it. Regtest disables PoW, so there is no
    /// solving step.
    pub async fn generate_blocks(&self, n: u32) -> Result<()> {
        for _ in 0..n {
            let url = self.rpc_url();
            let template_value = zebra_rpc_call(&url, "getblocktemplate", json!([]))
                .await
                .context("getblocktemplate")?;
            let template: BlockTemplateResponse =
                serde_json::from_value(template_value).context("decode block template")?;
            let block =
                proposal_block_from_template(&template, BlockTemplateTimeSource::default(), &self.net)
                    .map_err(|e| anyhow!("assemble block from template: {e}"))?;
            let block_hex = hex::encode(block.zcash_serialize_to_vec().context("serialize block")?);
            zebra_rpc_call(&url, "submitblock", json!([block_hex]))
                .await
                .context("submitblock")?;
        }
        Ok(())
    }
}

impl Drop for Zebrad {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// zebrad Regtest config for zebra 5.x. Note: no `[mining] debug_like_zcashd` (removed after
/// 2.x), `disable_pow = true` so submitted blocks need no PoW, and `enable_cookie_auth = false`
/// so lightwalletd can use the rpcuser/rpcpassword from its `zcash.conf`.
fn zebrad_toml(net_port: u16, rpc_port: u16) -> String {
    format!(
        r#"[network]
network = "Regtest"
listen_addr = "127.0.0.1:{net_port}"

[network.testnet_parameters]
disable_pow = true

[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1

[mining]
miner_address = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v"

[state]
ephemeral = true

[rpc]
listen_addr = "127.0.0.1:{rpc_port}"
enable_cookie_auth = false
"#
    )
}

// =============================== lightwalletd (indexer) ===============================

/// A running `lightwalletd` pointed at a regtest zebrad.
pub struct Lightwalletd {
    child: Child,
    /// gRPC port serving the lightwalletd `CompactTxStreamer` protocol.
    pub grpc_port: u16,
    _dir: tempfile::TempDir,
}

impl Lightwalletd {
    /// Launch `lightwalletd` against the given zebrad RPC port and wait until its gRPC server is up.
    pub async fn start(bin: &Path, zebrad_rpc_port: u16) -> Result<Lightwalletd> {
        let dir = tempfile::tempdir().context("create lightwalletd dir")?;
        let grpc_port = pick_port()?;
        let http_port = pick_port()?;
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir)?;

        // lightwalletd reads the node's RPC connection details from a zcash.conf-style file.
        let zcash_conf = dir.path().join("zcash.conf");
        std::fs::write(
            &zcash_conf,
            format!("rpcuser=zecdtest\nrpcpassword=zecdtest\nrpcbind=127.0.0.1\nrpcport={zebrad_rpc_port}\n"),
        )
        .context("write zcash.conf")?;

        let log_file = dir.path().join("lightwalletd.log");
        let child = Command::new(bin)
            .args([
                "--no-tls-very-insecure",
                "--grpc-bind-addr",
                &format!("127.0.0.1:{grpc_port}"),
                "--http-bind-addr",
                &format!("127.0.0.1:{http_port}"),
                "--data-dir",
                data_dir.to_str().unwrap(),
                "--log-file",
                log_file.to_str().unwrap(),
                "--zcash-conf-path",
                zcash_conf.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn lightwalletd ({})", bin.display()))?;

        let lwd = Lightwalletd { child, grpc_port, _dir: dir };
        lwd.wait_until_ready(&log_file).await?;
        Ok(lwd)
    }

    async fn wait_until_ready(&self, log_file: &Path) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Ok(log) = std::fs::read_to_string(log_file) {
                if log.contains("Starting insecure no-TLS (plaintext) server") {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                let log = std::fs::read_to_string(log_file).unwrap_or_default();
                bail!("lightwalletd did not become ready within 90s; log tail:\n{}", tail(&log, 20));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl Drop for Lightwalletd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// =============================== zecd (the system under test) ===============================

/// Locate the built `zecd` binary: `$ZECD_BIN` if set, else the parent crate's release build.
pub fn zecd_bin() -> PathBuf {
    if let Ok(p) = std::env::var("ZECD_BIN") {
        return PathBuf::from(p);
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(|p| p.join("target/release/zecd"))
        .unwrap_or_else(|| PathBuf::from("zecd"))
}

/// A running `zecd` daemon plus the HTTP client and credentials to drive it.
pub struct Zecd {
    child: Child,
    base_url: String,
    user: String,
    password: String,
    http: reqwest::Client,
    _datadir: tempfile::TempDir,
}

/// How `zecd` should reach the regtest lightwalletd, and what RPC port/creds to expose.
pub struct ZecdConfig {
    pub lightwalletd_port: u16,
    pub rpc_port: u16,
    pub rpc_user: String,
    pub rpc_password: String,
}

impl Zecd {
    /// Write a regtest `zecd.toml`, run `zecd init` (retried while lightwalletd catches up to the
    /// chain tip), then spawn the daemon. Returns once the RPC is up; call
    /// [`Zecd::wait_until_synced`] to wait for the scan to reach the tip.
    pub async fn start(cfg: &ZecdConfig) -> Result<Zecd> {
        let datadir = tempfile::tempdir().context("create zecd datadir")?;
        let bin = zecd_bin();
        if !bin.exists() {
            bail!(
                "zecd binary not found at {} - build it first (cargo build --release --bin zecd) \
                 or set $ZECD_BIN",
                bin.display()
            );
        }

        write_zecd_toml(datadir.path(), cfg).context("write zecd.toml")?;

        // `zecd init` contacts lightwalletd (get_latest_block + get_tree_state). Just after launch
        // lightwalletd may still be ingesting from zebrad, so retry, resetting the datadir between
        // attempts so a partial init can't wedge the next one.
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let init = Command::new(&bin)
                .args(["--datadir", datadir.path().to_str().unwrap(), "--regtest", "init"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .context("spawn zecd init")?;
            if init.status.success() {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "zecd init failed after retries ({}):\n{}",
                    init.status,
                    String::from_utf8_lossy(&init.stderr)
                );
            }
            reset_datadir(datadir.path(), cfg)?;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        let child = Command::new(&bin)
            .args(["--datadir", datadir.path().to_str().unwrap(), "--regtest", "run"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn zecd daemon")?;

        let zecd = Zecd {
            child,
            base_url: format!("http://127.0.0.1:{}/", cfg.rpc_port),
            user: cfg.rpc_user.clone(),
            password: cfg.rpc_password.clone(),
            http: reqwest::Client::new(),
            _datadir: datadir,
        };

        zecd.wait_until_rpc_up().await?;
        Ok(zecd)
    }

    /// Issue a JSON-RPC call, returning the `result` on success or an error carrying the
    /// Bitcoin Core error `code` (so tests can assert e.g. `-6` for insufficient funds).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({ "jsonrpc": "1.0", "id": "harness", "method": method, "params": params });
        let resp = self
            .http
            .post(&self.base_url)
            .basic_auth(&self.user, Some(&self.password))
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::transport(e.to_string()))?;
        let envelope: Value = resp
            .json()
            .await
            .map_err(|e| RpcError::transport(format!("decoding response: {e}")))?;
        if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
            return Err(RpcError::Rpc { code, message });
        }
        Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
    }

    /// The current best-block height as seen by zecd (`getblockcount`).
    pub async fn block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([]))
            .await
            .map_err(|e| anyhow!("{e}"))?
            .as_u64()
            .ok_or_else(|| anyhow!("getblockcount did not return a number"))
    }

    /// Poll until `getblockchaininfo.blocks` reaches `target` (zecd has scanned to the tip).
    pub async fn wait_until_synced(&self, target: u64, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(info) = self.call("getblockchaininfo", json!([])).await {
                let blocks = info.get("blocks").and_then(|b| b.as_u64()).unwrap_or(0);
                if blocks >= target {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("zecd did not sync to height {target} within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn wait_until_rpc_up(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.call("uptime", json!([])).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("zecd RPC did not come up within 30s");
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

impl Drop for Zecd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A JSON-RPC failure: either a transport problem or a Bitcoin-Core-style `{code, message}`.
#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Rpc { code: i64, message: String },
}

impl RpcError {
    fn transport(s: String) -> Self {
        RpcError::Transport(s)
    }
    /// The Bitcoin Core error code, if this was an RPC-level error.
    pub fn code(&self) -> Option<i64> {
        match self {
            RpcError::Rpc { code, .. } => Some(*code),
            RpcError::Transport(_) => None,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(s) => write!(f, "transport error: {s}"),
            RpcError::Rpc { code, message } => write!(f, "rpc error {code}: {message}"),
        }
    }
}

// =============================== helpers ===============================

/// JSON-RPC 2.0 call to zebrad; returns the `result` or an error carrying the message.
async fn zebra_rpc_call(url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .context("zebra rpc request")?;
    let envelope: Value = resp.json().await.context("decode zebra rpc response")?;
    if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
        bail!("zebra rpc error from {method}: {err}");
    }
    Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
}

fn tail(s: &str, lines: usize) -> String {
    let all: Vec<&str> = s.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn reset_datadir(datadir: &Path, cfg: &ZecdConfig) -> Result<()> {
    for entry in std::fs::read_dir(datadir).context("read datadir for reset")? {
        let path = entry?.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
    write_zecd_toml(datadir, cfg)
}

fn write_zecd_toml(datadir: &Path, cfg: &ZecdConfig) -> Result<()> {
    let toml = format!(
        r#"network = "regtest"
datadir = "{datadir}"
default_wallet = "default"

[wallets.default]
dir = "{datadir}/default"

[lightwalletd]
server = "127.0.0.1:{lwd}"
connection = "direct"
tls = "no"

[rpc]
bind = "127.0.0.1"
port = {rpc_port}
user = "{user}"
password = "{password}"

[keys]
auto_unlock = true

[sync]
interval_secs = 2

[health]
enabled = true
bind = "127.0.0.1"
port = {health_port}
"#,
        datadir = datadir.display(),
        lwd = cfg.lightwalletd_port,
        rpc_port = cfg.rpc_port,
        user = cfg.rpc_user,
        password = cfg.rpc_password,
        health_port = cfg.rpc_port + 1,
    );
    std::fs::write(datadir.join("zecd.toml"), toml)?;
    Ok(())
}
