//! Helpers for driving a real `zecd` daemon over its Bitcoin-Core-style JSON-RPC.
//!
//! These are deliberately independent of the regtest orchestration (zebra/lightwalletd): the
//! `zecd` side is stable and fully under our control, so it lives here as a small, reusable
//! client. The actual end-to-end scenario (spin up regtest, mine, drive zecd) lives in
//! `tests/regtest_e2e.rs`.
//!
//! `zecd` is launched as a subprocess (the built release binary), so this exercises the real
//! RPC server, auth, sync loop and wallet actor - not just library functions.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

/// Locate the built `zecd` binary: `$ZECD_BIN` if set, else the parent crate's release build.
pub fn zecd_bin() -> PathBuf {
    if let Ok(p) = std::env::var("ZECD_BIN") {
        return PathBuf::from(p);
    }
    // `regtest-harness/` sits next to zecd's `target/`.
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
    // Owns the temp datadir; dropped (and removed) when the daemon is torn down.
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
    /// Write a regtest `zecd.toml`, run `zecd init` (which contacts lightwalletd to fetch the
    /// birthday tree state), then spawn the daemon. Returns once the process is up; call
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

        // One-time init: creates the wallet, age identity, and account. This connects to
        // lightwalletd, so the regtest node must already have blocks.
        let init = Command::new(&bin)
            .args(["--datadir", datadir.path().to_str().unwrap(), "--regtest", "init"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("spawn zecd init")?;
        if !init.status.success() {
            bail!(
                "zecd init failed ({}):\n{}",
                init.status,
                String::from_utf8_lossy(&init.stderr)
            );
        }

        // Run the daemon.
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
        Ok(self
            .call("getblockcount", json!([]))
            .await
            .map_err(|e| anyhow!("{e}"))?
            .as_u64()
            .ok_or_else(|| anyhow!("getblockcount did not return a number"))?)
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
        // Keep the health port distinct from the RPC port.
        health_port = cfg.rpc_port + 1,
    );
    std::fs::write(datadir.join("zecd.toml"), toml)?;
    Ok(())
}
