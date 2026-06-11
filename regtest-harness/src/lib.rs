//! End-to-end regtest harness for `zecd`.
//!
//! Orchestrates the **Zcash Foundation** regtest stack directly - `zebrad` (Regtest, PoW
//! disabled) + `lightwalletd` - and drives the real `zecd` daemon over its Bitcoin-Core-style
//! JSON-RPC. There is intentionally **no `zingo-infra`/`zcash_local_net` dependency**, and no
//! compile-time zebra dependency either: blocks are mined with zebrad's own Regtest-only
//! `generate` RPC (zebra ≥ 2.0.0), which runs the template→assemble→submit flow server-side
//! against the node's own network parameters. The harness is a pure black-box JSON-RPC driver,
//! so it works unmodified against any zebrad release.
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

/// Pick an unused loopback TCP port (bind `:0`, read the port, release it). Racy by nature, but
/// fine for a single-threaded test run.
pub fn pick_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Resolve a required external binary from `$<env_var>`, returning `None` if unset or missing so
/// callers can skip the live test cleanly.
pub fn resolve_bin(env_var: &str) -> Option<PathBuf> {
    std::env::var(env_var)
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

// =============================== zebrad (Regtest validator) ===============================

/// Height at which NU6.1 and NU6.2 activate on our regtest chain. NU5/NU6 are active from genesis;
/// NU6.1's activation block requires ZIP-271 lockbox disbursements out of the deferred pool, which
/// only accrues once NU6 is live - so NU6.1/NU6.2 activate a few blocks in, after a pool exists.
/// Must match `zecd`'s `network::regtest`.
const NU6_2_ACTIVATION_HEIGHT: u32 = 4;
/// ZIP-271 one-time lockbox disbursement paid in the NU6.1 activation block's coinbase. A P2SH
/// regtest address and a token amount (<= the pool accrued by [`NU6_2_ACTIVATION_HEIGHT`]).
const LOCKBOX_DISBURSEMENT_ADDR: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const LOCKBOX_DISBURSEMENT_ZATS: u64 = 1;

/// A throwaway transparent address used as zebra's coinbase recipient when the caller doesn't need
/// to control the coinbase (the unfunded e2e). Funded flows pass the funding wallet's own address.
const DEFAULT_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";

/// A running `zebrad` Regtest node.
pub struct Zebrad {
    child: Child,
    /// JSON-RPC port (cookie auth disabled so lightwalletd can connect).
    pub rpc_port: u16,
    net_port: u16,
    bin: PathBuf,
    config_path: PathBuf,
    _dir: tempfile::TempDir,
}

/// Spawn `zebrad --config <config_path> start`. Set ZEBRAD_STDERR to a file path to capture its
/// logs (zebra logs to stdout, so route both there); otherwise discard them to keep test output
/// clean.
fn spawn_zebrad(bin: &Path, config_path: &Path) -> Result<Child> {
    let (out, err) = match std::env::var_os("ZEBRAD_STDERR") {
        Some(p) => {
            let f = std::fs::File::create(&p).context("create ZEBRAD_STDERR file")?;
            let f2 = f.try_clone().context("clone ZEBRAD_STDERR file")?;
            (Stdio::from(f), Stdio::from(f2))
        }
        None => (Stdio::null(), Stdio::null()),
    };
    let mut cmd = Command::new(bin);
    // zebrad reads `ZEBRA_*` environment variables as config overrides (config-rs), and an
    // unrelated variable like `ZEBRA_TAG` in a CI job makes it exit at startup with
    // "Configuration error: unknown field". Scrub the prefix so the harness only ever
    // configures zebrad through the config file it writes.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("ZEBRA_") {
            cmd.env_remove(key);
        }
    }
    cmd.args(["--config", config_path.to_str().unwrap(), "start"])
        .stdout(out)
        .stderr(err)
        .spawn()
        .with_context(|| format!("spawn zebrad ({})", bin.display()))
}

impl Zebrad {
    /// Launch `zebrad` in Regtest mode (mining to a throwaway address) and wait until its
    /// JSON-RPC answers.
    pub async fn start(bin: &Path) -> Result<Zebrad> {
        Self::start_with_miner(bin, DEFAULT_MINER_ADDRESS).await
    }

    /// Launch `zebrad` mining its coinbase to `miner_address`, so a wallet that controls that
    /// address can spend the matured coinbase (used to fund the Orchard wallet under test).
    pub async fn start_with_miner(bin: &Path, miner_address: &str) -> Result<Zebrad> {
        let dir = tempfile::tempdir().context("create zebrad dir")?;
        let rpc_port = pick_port()?;
        let net_port = pick_port()?;
        let config_path = dir.path().join("zebrad.toml");
        let cache_dir = dir.path().join("state");
        std::fs::write(
            &config_path,
            zebrad_toml(
                net_port,
                rpc_port,
                miner_address,
                &cache_dir.to_string_lossy(),
            ),
        )
        .context("write zebrad.toml")?;
        let child = spawn_zebrad(bin, &config_path)?;
        let mut zebrad = Zebrad {
            child,
            rpc_port,
            net_port,
            bin: bin.to_path_buf(),
            config_path,
            _dir: dir,
        };
        zebrad.wait_until_rpc_up().await?;
        Ok(zebrad)
    }

    /// Restart `zebrad` mining to a different address, preserving the chain (persistent state).
    /// Used by the funded e2e to stop minting coinbases to the funder so its existing coinbases
    /// can age past maturity while a throwaway address mines the tail.
    pub async fn restart_with_miner(&mut self, miner_address: &str) -> Result<()> {
        // Clean shutdown via the regtest `stop` RPC (raises SIGINT) so zebra backs up its
        // non-finalized state. A SIGKILL would drop the recent, not-yet-finalized blocks and reset
        // the chain to genesis - losing the funder's coinbases.
        let _ = self.rpc("stop", json!([])).await;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        let cache_dir = self._dir.path().join("state");
        std::fs::write(
            &self.config_path,
            zebrad_toml(
                self.net_port,
                self.rpc_port,
                miner_address,
                &cache_dir.to_string_lossy(),
            ),
        )
        .context("rewrite zebrad.toml for restart")?;
        self.child = spawn_zebrad(&self.bin, &self.config_path)?;
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.rpc_port)
    }

    async fn wait_until_rpc_up(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut last_err = anyhow!("no getblocktemplate attempt completed");
        loop {
            // A dead zebrad can never become mineable - fail immediately with the exit status
            // instead of burning the whole timeout on connection-refused.
            if let Ok(Some(status)) = self.child.try_wait() {
                bail!(
                    "zebrad exited during startup ({status}); \
                     set ZEBRAD_STDERR=<file> to capture its logs"
                );
            }
            // `getblocktemplate` succeeds only once zebra's RPC is up *and* it considers itself
            // synced to the chain tip (mempool active) - which is exactly the precondition for
            // `generate_blocks`. On a fresh node, and especially under the load of several test
            // nodes running at once, this readiness lags RPC availability by a moment, so we poll
            // the template endpoint itself rather than just `getblockchaininfo`.
            match zebra_rpc_call(&self.rpc_url(), "getblocktemplate", json!([])).await {
                Ok(_) => return Ok(()),
                Err(e) => last_err = e,
            }
            if Instant::now() >= deadline {
                bail!("zebrad did not become mineable within 120s; last error: {last_err:#}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Issue a raw JSON-RPC call to this zebrad (test/diagnostic helper).
    pub async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        zebra_rpc_call(&self.rpc_url(), method, params).await
    }

    /// Mine `n` blocks via zebrad's Regtest-only `generate` RPC (zebra ≥ 2.0.0). Server-side it
    /// runs the same `getblocktemplate` → assemble → `submitblock` flow zebra's own regtest tests
    /// use, against the node's own network parameters - so the harness needs no zebra crates and
    /// can't drift from the running node's consensus rules. Regtest disables PoW, so there is no
    /// solving step.
    pub async fn generate_blocks(&self, n: u32) -> Result<()> {
        let hashes = zebra_rpc_call(&self.rpc_url(), "generate", json!([n]))
            .await
            .context("generate")?;
        // `generate` returns the array of mined block hashes; a short array means some block
        // was rejected - fail loudly so the chain can't silently stop advancing.
        let mined = hashes.as_array().map(|a| a.len()).unwrap_or(0);
        if mined != n as usize {
            bail!("generate mined {mined} of {n} requested blocks: {hashes}");
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
fn zebrad_toml(net_port: u16, rpc_port: u16, miner_address: &str, cache_dir: &str) -> String {
    let nu6_2 = NU6_2_ACTIVATION_HEIGHT;
    let lockbox_addr = LOCKBOX_DISBURSEMENT_ADDR;
    let lockbox_amount = LOCKBOX_DISBURSEMENT_ZATS;
    format!(
        r#"[network]
network = "Regtest"
listen_addr = "127.0.0.1:{net_port}"

[network.testnet_parameters]
disable_pow = true

# NU5/NU6 from genesis, then NU6.1+NU6.2 at NU6_2_ACTIVATION_HEIGHT. NU6.1 can't activate at
# height 1: its activation block must carry ZIP-271 one-time lockbox disbursements, and the
# deferred (lockbox) pool only accrues once NU6 is active - so we let NU6 run for a few blocks to
# build a pool, then disburse a token amount at the NU6.1/NU6.2 activation block. zebra's
# getblocktemplate emits the disbursement output automatically from the config below.
# devtool's and zecd's regtest networks must match these heights (network::regtest / regtest_local).
[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = {nu6_2}
"NU6.2" = {nu6_2}

# A deferred (lockbox) funding stream so the pool has something to disburse at NU6.1.
[[network.testnet_parameters.funding_streams]]
[network.testnet_parameters.funding_streams.height_range]
start = 1
end = 1_000_000
[[network.testnet_parameters.funding_streams.recipients]]
receiver = "Deferred"
numerator = 12
addresses = []

# The ZIP-271 one-time disbursement paid at the NU6.1 activation block. The amount need only be
# <= the pool accrued by then; the residual stays in the lockbox.
[[network.testnet_parameters.lockbox_disbursements]]
address = "{lockbox_addr}"
amount = {lockbox_amount}

[mining]
miner_address = "{miner_address}"

[state]
# Persistent (not ephemeral) so the chain survives a restart with a different miner address - the
# funded e2e mines the funder's coinbases, then restarts mining to a throwaway address to age them
# past coinbase maturity (see Zebrad::restart_with_miner).
ephemeral = false
cache_dir = "{cache_dir}"

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
        let grpc_port = pick_port()?;
        Self::start_on(bin, zebrad_rpc_port, grpc_port).await
    }

    /// Launch on a *fixed* gRPC port. Used by the fault tests to bring lightwalletd back on
    /// the same address a running zecd is configured for (a fresh data dir re-ingests the
    /// chain from zebra, which takes seconds on a regtest chain).
    pub async fn start_on(bin: &Path, zebrad_rpc_port: u16, grpc_port: u16) -> Result<Lightwalletd> {
        let dir = tempfile::tempdir().context("create lightwalletd dir")?;
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

        let lwd = Lightwalletd {
            child,
            grpc_port,
            _dir: dir,
        };
        lwd.wait_until_ready(&log_file).await?;
        Ok(lwd)
    }

    /// Kill the process, simulating an upstream outage. The gRPC port is freed (new
    /// connections are refused) and can be reused by a later [`Lightwalletd::start_on`].
    pub fn stop(self) {
        // Drop runs kill + wait.
    }

    /// Pause the process with SIGSTOP, simulating a *hung* upstream: the kernel keeps its
    /// sockets alive - TCP connects succeed and segments are ACKed - but no request is ever
    /// answered. This is the failure mode a kill can't reproduce (a dead process refuses
    /// connections immediately) and the one only HTTP/2 keepalive / per-RPC deadlines can
    /// detect. Resume with [`Lightwalletd::resume`].
    pub fn pause(&self) -> Result<()> {
        signal_process(self.child.id(), "STOP")
    }

    /// Resume a [`Lightwalletd::pause`]d process (SIGCONT); it picks up where it stopped.
    pub fn resume(&self) -> Result<()> {
        signal_process(self.child.id(), "CONT")
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
                bail!(
                    "lightwalletd did not become ready within 90s; log tail:\n{}",
                    tail(&log, 20)
                );
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

// =============================== funder (zcash-devtool) ===============================

/// A valid 24-word BIP-39 test mnemonic (the canonical all-zero-entropy vector). Regtest only - it
/// controls throwaway coinbase funds, never anything of value.
const FUNDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

/// Drives the `zcash-devtool` binary as a funding wallet. It controls zebra's coinbase (which is
/// mined to its address), shields the matured transparent coinbase into Orchard, and sends Orchard
/// funds to the `zecd` wallet under test. Resolve the binary via `$DEVTOOL_BIN`.
///
/// Regtest can't mine a coinbase straight into an Orchard note that `zecd` (Orchard-only) would
/// see, so this is how we get funds into `zecd`: mine transparent coinbase → mature (101 blocks) →
/// shield to Orchard → send to `zecd`'s unified address.
pub struct Funder {
    bin: PathBuf,
    dir: tempfile::TempDir,
}

impl Funder {
    /// Derive the funder's default transparent address offline (no chain, no wallet) from its
    /// fixed mnemonic, so zebra can be told to mine its coinbase here *before* any chain exists.
    /// Mining straight to the funder keeps everything on one chain, so the wallet's birthday anchor
    /// stays valid (a throwaway chain would hand the wallet a wrong note-commitment anchor).
    pub fn derive_transparent_address(bin: &Path) -> Result<String> {
        let output = Command::new(bin)
            .args([
                "wallet",
                "derive-address",
                "--network",
                "regtest",
                "--mnemonic",
                FUNDER_MNEMONIC,
            ])
            .output()
            .context("spawn devtool derive-address")?;
        if !output.status.success() {
            bail!(
                "devtool derive-address failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let out = String::from_utf8_lossy(&output.stdout);
        out.lines()
            .find_map(|line| line.split("Transparent Address:").nth(1))
            .map(|addr| addr.trim().to_string())
            .ok_or_else(|| anyhow!("no Transparent Address in derive-address output:\n{out}"))
    }

    /// Initialise the funding wallet against a lightwalletd. Non-interactive via `--mnemonic`;
    /// `--birthday 2` is the lowest height with a tree state (init fetches `GetTreeState(birthday-1)`,
    /// which needs a real block - `birthday 0/1` requests genesis and is rejected). The funder's
    /// transparent coinbase is detected regardless of birthday.
    pub fn init(bin: &Path, lwd_port: u16) -> Result<Funder> {
        let dir = tempfile::tempdir().context("create funder dir")?;
        let funder = Funder {
            bin: bin.to_path_buf(),
            dir,
        };
        let identity = funder.identity();
        funder.run(
            "init",
            &[
                "--name",
                "funder",
                "--network",
                "regtest",
                "--identity",
                &identity,
                "--mnemonic",
                FUNDER_MNEMONIC,
                "--birthday",
                "2",
            ],
            Some(lwd_port),
        )?;
        Ok(funder)
    }

    fn identity(&self) -> String {
        self.dir
            .path()
            .join("identity.txt")
            .to_string_lossy()
            .into_owned()
    }

    fn wallet_dir(&self) -> String {
        self.dir.path().to_string_lossy().into_owned()
    }

    /// The funder's unified address (parsed from `list-addresses`), used as zebra's miner address.
    pub fn unified_address(&self) -> Result<String> {
        let out = self.run("list-addresses", &[], None)?;
        out.lines()
            .find_map(|line| line.split("Default Address:").nth(1))
            .map(|addr| addr.trim().to_string())
            .ok_or_else(|| anyhow!("no Default Address in devtool list-addresses output:\n{out}"))
    }

    /// Scan the chain via lightwalletd to pick up new transactions / UTXOs.
    pub fn sync(&self, lwd_port: u16) -> Result<()> {
        self.run("sync", &[], Some(lwd_port)).map(|_| ())
    }

    /// Shield all spendable transparent funds (the matured coinbase) into Orchard.
    pub fn shield(&self, lwd_port: u16) -> Result<()> {
        let identity = self.identity();
        self.run("shield", &["--identity", &identity], Some(lwd_port))
            .map(|_| ())
    }

    /// Send `zatoshis` to `to_address` (an Orchard/unified address).
    pub fn send(&self, lwd_port: u16, to_address: &str, zatoshis: u64) -> Result<()> {
        let identity = self.identity();
        let value = zatoshis.to_string();
        self.run(
            "send",
            &[
                "--identity",
                &identity,
                "--address",
                to_address,
                "--value",
                &value,
            ],
            Some(lwd_port),
        )
        .map(|_| ())
    }

    /// Run `zcash-devtool wallet -w <dir> <subcommand> <extra...> [--server .. --connection direct]`.
    fn run(&self, subcommand: &str, extra: &[&str], lwd_port: Option<u16>) -> Result<String> {
        let mut args: Vec<String> = vec![
            "wallet".into(),
            "-w".into(),
            self.wallet_dir(),
            subcommand.into(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        if let Some(port) = lwd_port {
            args.extend([
                "--server".into(),
                format!("127.0.0.1:{port}"),
                "--connection".into(),
                "direct".into(),
            ]);
        }
        let output = Command::new(&self.bin)
            .args(&args)
            .output()
            .with_context(|| format!("spawn devtool {subcommand}"))?;
        if !output.status.success() {
            bail!(
                "devtool {subcommand} failed ({}):\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                tail(&String::from_utf8_lossy(&output.stderr), 30),
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
    /// Primary lightwalletd gRPC port.
    pub lightwalletd_port: u16,
    /// Optional fallback lightwalletd (for the failover tests); listed after the primary.
    pub fallback_lightwalletd_port: Option<u16>,
    pub rpc_port: u16,
    pub rpc_user: String,
    pub rpc_password: String,
    /// `[sync] rebroadcast_secs` - tight by default so outage tests don't idle a minute.
    pub rebroadcast_secs: u64,
    /// `[lightwalletd] primary_recheck_secs` - how fast a recovered primary is re-adopted.
    pub primary_recheck_secs: u64,
}

impl ZecdConfig {
    /// Test-friendly defaults: `user`/`pass` credentials, no fallback, 2s rebroadcast,
    /// 3s primary re-check, fast reconnect backoff (written by [`write_zecd_toml`]).
    pub fn new(lightwalletd_port: u16, rpc_port: u16) -> ZecdConfig {
        ZecdConfig {
            lightwalletd_port,
            fallback_lightwalletd_port: None,
            rpc_port,
            rpc_user: "user".to_string(),
            rpc_password: "pass".to_string(),
            rebroadcast_secs: 2,
            primary_recheck_secs: 3,
        }
    }
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
                .args([
                    "--datadir",
                    datadir.path().to_str().unwrap(),
                    "--regtest",
                    "init",
                ])
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
            .args([
                "--datadir",
                datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
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
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
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

/// Send a named signal (e.g. `STOP`, `CONT`) to a process via the portable `kill` binary
/// (avoids a libc dependency for the harness's two niche uses).
fn signal_process(pid: u32, sig: &str) -> Result<()> {
    let status = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .with_context(|| format!("spawn kill -{sig} {pid}"))?;
    anyhow::ensure!(status.success(), "kill -{sig} {pid} exited with {status}");
    Ok(())
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
    let mut servers = format!(r#""127.0.0.1:{}""#, cfg.lightwalletd_port);
    if let Some(fb) = cfg.fallback_lightwalletd_port {
        servers.push_str(&format!(r#", "127.0.0.1:{fb}""#));
    }
    // Fast reconnect backoff (1..2s) so outage-recovery tests converge quickly.
    let toml = format!(
        r#"network = "regtest"
datadir = "{datadir}"
default_wallet = "default"

[wallets.default]
dir = "{datadir}/default"

[lightwalletd]
servers = [{servers}]
connection = "direct"
tls = "no"
connect_timeout_secs = 5
reconnect_base_secs = 1
reconnect_max_secs = 2
primary_recheck_secs = {primary_recheck}

[rpc]
bind = "127.0.0.1"
port = {rpc_port}
user = "{user}"
password = "{password}"

[keys]
auto_unlock = true

[sync]
interval_secs = 2
rebroadcast_secs = {rebroadcast}

[health]
enabled = true
bind = "127.0.0.1"
port = {health_port}
"#,
        datadir = datadir.display(),
        primary_recheck = cfg.primary_recheck_secs,
        rpc_port = cfg.rpc_port,
        user = cfg.rpc_user,
        password = cfg.rpc_password,
        rebroadcast = cfg.rebroadcast_secs,
        health_port = cfg.rpc_port + 1,
    );
    std::fs::write(datadir.join("zecd.toml"), toml)?;
    Ok(())
}
