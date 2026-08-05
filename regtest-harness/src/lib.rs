//! End-to-end regtest harness for `zecd`.
//!
//! Orchestrates a `zebrad` (Regtest, PoW disabled) node and drives the real `zecd` daemon over
//! its Bitcoin-Core-style JSON-RPC - `zecd` talks straight to zebrad. There is intentionally
//! **no `zingo-infra`/`zcash_local_net` dependency**, and no compile-time zebra dependency
//! either: blocks are mined with zebrad's own Regtest-only `generate` RPC (zebra ≥ 2.0.0),
//! which runs the template->assemble->submit flow server-side against the node's own network
//! parameters. The harness is a pure black-box JSON-RPC driver, so it works unmodified against
//! any zebrad release.
//!
//! The funded tests bring up a second `zecd` as the [funding wallet](Funder). It talks straight
//! to the same zebrad over JSON-RPC, so the whole tier needs nothing but a node.
//!
//! Binaries are supplied by the caller via `$ZEBRAD_BIN` (see [`resolve_bin`]); in CI zebrad is
//! extracted from the official `zfnd/zebra` image. `zecd` itself is the built release binary; the
//! funder's `zecd` comes from `$ZECD_FUNDER_BIN` (see [`funder_bin`]).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

/// The default loopback port window probed by [`pick_port`]: 20000..32000, entirely below the
/// 32768 ephemeral floor. Narrowed per process by `ZECD_REGTEST_PORT_LO`/`_SPAN` - see
/// [`port_window`].
const DEFAULT_PORT_LO: u16 = 20000;
const DEFAULT_PORT_SPAN: u16 = 12000;

/// The loopback port window this process probes, as `(lo, span)`.
///
/// Defaults to the whole non-ephemeral range. `ZECD_REGTEST_PORT_LO` and `ZECD_REGTEST_PORT_SPAN`
/// narrow it to a slice, which is how several harness test binaries run **concurrently**: the CI
/// driver (`run-tests.sh`) hands each one a disjoint slice, so two processes can never probe the
/// same port. Without that, [`pick_port`]'s probe-then-release-then-bind-later pattern leaves a
/// window in which a sibling process binds the port between our probe and its real owner's bind -
/// harmless when the binaries run one at a time (as they did when this was written), a flake
/// source the moment they overlap.
fn port_window() -> (u16, u16) {
    fn from_env(var: &str) -> Option<u16> {
        std::env::var(var)
            .ok()?
            .trim()
            .parse()
            .ok()
            .filter(|v| *v > 0)
    }
    let lo = from_env("ZECD_REGTEST_PORT_LO").unwrap_or(DEFAULT_PORT_LO);
    let span = from_env("ZECD_REGTEST_PORT_SPAN").unwrap_or(DEFAULT_PORT_SPAN);
    // Never let a bad slice push the window into (or past) the ephemeral range.
    let span = span.min(32768u16.saturating_sub(lo));
    (lo, span)
}

/// Pick an unused loopback TCP port for a daemon to bind later.
///
/// Deliberately NOT `bind(":0")`-and-release: `:0` hands out ports from the kernel's *ephemeral*
/// range (32768-60999 on Linux), where any concurrent outbound connection - zebra↔zecd RPC,
/// reqwest clients, the mempool poller - can grab the released port before its real owner binds
/// it. That race cost a CI run (zecd's health server lost its pre-picked port to a client socket
/// and the run continued without health endpoints). Instead, probe sequentially from a
/// PID-seeded offset in a range *below* the ephemeral floor, which client sockets never touch;
/// the cursor never re-probes a handed-out port within a process, so back-to-back picks can't
/// collide with each other either.
///
/// Every probe claims its index with a single `fetch_add`, which is what makes concurrent callers
/// safe. An earlier version loaded the cursor, probed, and stored the advanced value as three
/// separate operations - fine while the harness ran one test at a time, but two threads would then
/// read the same cursor value, probe the same port, both find it bindable (neither has bound it
/// yet - that happens later, in the daemon) and both return it. The second daemon to start died
/// with `Address already in use`. An atomic read-modify-write per attempt gives every caller a
/// distinct index, and because the counter only ever moves forward no thread can re-probe a port
/// another one is still holding un-bound.
pub fn pick_port() -> Result<u16> {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::OnceLock;
    let (lo, span) = port_window();
    if span == 0 {
        bail!("empty loopback port window at {lo}");
    }
    static CURSOR: OnceLock<AtomicU32> = OnceLock::new();
    let cursor = CURSOR.get_or_init(|| AtomicU32::new(std::process::id()));
    for _ in 0..span {
        let off = cursor.fetch_add(1, Ordering::Relaxed);
        let port = lo + (off % u32::from(span)) as u16;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no free loopback port in {lo}..{}", lo + span)
}

/// Resolve a required external binary from `$<env_var>`, returning `None` if unset or missing so
/// callers can skip the live test cleanly.
pub fn resolve_bin(env_var: &str) -> Option<PathBuf> {
    std::env::var(env_var)
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

/// Which zebrad-dialect node the live tier drives, selected by the `ZECD_REGTEST_NODE`
/// environment variable. Both nodes speak the same Bitcoin-Core-style JSON-RPC dialect, accept
/// the same regtest config, and mine via the same Regtest-only `generate` RPC, so the harness
/// code path is *identical* - only the binary (and the env var pointing at it) differs. This is
/// what makes the harness a true black-box driver: `zecd` can't tell the two apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegtestNode {
    /// The Zcash Foundation's `zebrad` (the default). Binary from `$ZEBRAD_BIN`.
    Zebra,
    /// `zakurad` - Zakura, a performance-oriented `zebrad` fork that keeps zebra's RPC and
    /// config surface (<https://github.com/zakura-core/zakura>). Binary from `$ZAKURAD_BIN`.
    Zakura,
}

impl RegtestNode {
    /// Resolve the node from `ZECD_REGTEST_NODE` (case-insensitive; default [`RegtestNode::Zebra`]).
    /// An unrecognised value falls back to zebra with a warning so a typo can't silently pick the
    /// wrong backend.
    pub fn from_env() -> RegtestNode {
        match std::env::var("ZECD_REGTEST_NODE") {
            Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
                "" | "zebra" | "zebrad" => RegtestNode::Zebra,
                "zakura" | "zakurad" => RegtestNode::Zakura,
                other => {
                    eprintln!(
                        "WARN ZECD_REGTEST_NODE={other:?} is not recognised; \
                         defaulting to zebra (valid: zebra, zakura)"
                    );
                    RegtestNode::Zebra
                }
            },
            Err(_) => RegtestNode::Zebra,
        }
    }

    /// The env var holding this node's binary path (`ZEBRAD_BIN` / `ZAKURAD_BIN`).
    pub fn bin_env(self) -> &'static str {
        match self {
            RegtestNode::Zebra => "ZEBRAD_BIN",
            RegtestNode::Zakura => "ZAKURAD_BIN",
        }
    }

    /// A short human label (`zebra` / `zakura`) for skip messages and diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            RegtestNode::Zebra => "zebra",
            RegtestNode::Zakura => "zakura",
        }
    }
}

/// Resolve the [selected node](RegtestNode::from_env)'s binary (`$ZEBRAD_BIN` or `$ZAKURAD_BIN`),
/// returning `None` if unset or missing so callers can skip the live test cleanly. This is the
/// backend-agnostic replacement for `resolve_bin("ZEBRAD_BIN")`: the default is zebra, and setting
/// `ZECD_REGTEST_NODE=zakura` points the whole suite at `zakurad` instead.
pub fn resolve_node_bin() -> Option<PathBuf> {
    resolve_bin(RegtestNode::from_env().bin_env())
}

// =============================== zebrad (Regtest validator) ===============================

/// Height at which NU6.1 and NU6.2 activate on our regtest chain. NU5/NU6 are active from genesis;
/// NU6.1's activation block requires ZIP-271 lockbox disbursements out of the deferred pool, which
/// only accrues once NU6 is live - so NU6.1/NU6.2 activate a few blocks in, after a pool exists.
/// Must match `zecd`'s `network::regtest`.
const NU6_2_ACTIVATION_HEIGHT: u32 = 4;
/// Height at which NU6.3 (ironwood) activates on the regtest chain. NU6.3 is active on mainnet and
/// testnet, so the harness chain activates it too - every regtest flow runs on the pool real users
/// are on. This value is the canonical reference for the cross-component schedule: it MUST equal
/// `zecd`'s `network::regtest()` `nu6_3` height, which both the wallet under test and the
/// [`Funder`] pick up from `ZECD_REGTEST_NU63_HEIGHT` - a mismatch diverges the NU6.3 consensus
/// branch id and zebra rejects the tx (loud failure, not silent). Needs zebrad >= 6.2.2, which
/// accepts the `"NU6.3"` activation-height key.
pub const NU6_3_ACTIVATION_HEIGHT: u32 = 8;
/// ZIP-271 one-time lockbox disbursement paid in the NU6.1 activation block's coinbase. A P2SH
/// regtest address and a token amount (<= the pool accrued by [`NU6_2_ACTIVATION_HEIGHT`]).
const LOCKBOX_DISBURSEMENT_ADDR: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const LOCKBOX_DISBURSEMENT_ZATS: u64 = 1;

/// A throwaway transparent address used as zebra's coinbase recipient when the caller doesn't need
/// to control the coinbase: the unfunded e2e, and the seed blocks a funded run mines before the
/// [`Funder`] exists. Nothing in the harness holds its key.
pub const SEED_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";

/// A second throwaway transparent address, distinct from [`SEED_MINER_ADDRESS`], for tests that
/// need two *different* coinbase recipients - the reorg e2e mines its replacement chain to this
/// one so the replacement blocks are guaranteed to differ from the originals.
pub const ALT_MINER_ADDRESS: &str = "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86";

/// A running `zebrad`-dialect Regtest node. Drives whichever binary the caller passes - the
/// Zcash Foundation's `zebrad` or Zakura's `zakurad` (see [`RegtestNode`]) - the same way: both
/// take the same regtest config and mine via the same Regtest-only `generate` RPC.
pub struct Zebrad {
    child: Child,
    /// JSON-RPC port (cookie auth disabled so zecd can connect).
    pub rpc_port: u16,
    net_port: u16,
    bin: PathBuf,
    config_path: PathBuf,
    /// NU6.3 (ironwood) activation height. Preserved across `restart_with_miner` so the rebuilt
    /// config keeps the same schedule.
    nu6_3_height: u32,
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
    // zebrad/zakurad read `ZEBRA_*` (resp. `ZAKURA_*`) environment variables as config overrides
    // (config-rs), and an unrelated variable like `ZEBRA_TAG` in a CI job makes the node exit at
    // startup with "Configuration error: unknown field". Scrub both prefixes so the harness only
    // ever configures the node through the config file it writes. (`ZEBRAD_BIN`/`ZAKURAD_BIN`
    // don't match - no trailing underscore after the prefix - so the binary selectors survive.)
    for (key, _) in std::env::vars_os() {
        let key_str = key.to_string_lossy();
        if key_str.starts_with("ZEBRA_") || key_str.starts_with("ZAKURA_") {
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
        Self::start_with_miner(bin, SEED_MINER_ADDRESS).await
    }

    /// Launch `zebrad` mining its coinbase to `miner_address`, so a wallet that controls that
    /// address can spend the matured coinbase (used to fund the shielded wallet under test).
    /// The chain always activates NU6.3 at [`NU6_3_ACTIVATION_HEIGHT`], matching mainnet/testnet.
    pub async fn start_with_miner(bin: &Path, miner_address: &str) -> Result<Zebrad> {
        Self::start_inner(bin, miner_address, NU6_3_ACTIVATION_HEIGHT).await
    }

    async fn start_inner(bin: &Path, miner_address: &str, nu6_3_height: u32) -> Result<Zebrad> {
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
                nu6_3_height,
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
            nu6_3_height,
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
                self.nu6_3_height,
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
    /// runs the same `getblocktemplate` -> assemble -> `submitblock` flow zebra's own regtest tests
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

    /// Pause the process with SIGSTOP, simulating a *hung* upstream: the kernel keeps its
    /// sockets alive - TCP connects succeed and segments are ACKed - but no JSON-RPC request is
    /// ever answered. This is the failure mode a kill can't reproduce (a dead process refuses
    /// connections immediately) and the one only the client's per-RPC deadlines can detect.
    /// Resume with [`Zebrad::resume`].
    pub fn pause(&self) -> Result<()> {
        signal_process(self.child.id(), "STOP")
    }

    /// Resume a [`Zebrad::pause`]d process (SIGCONT); it picks up where it stopped.
    pub fn resume(&self) -> Result<()> {
        signal_process(self.child.id(), "CONT")
    }
}

impl Drop for Zebrad {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// zebrad Regtest config for zebra 6.x. Note: no `[mining] debug_like_zcashd` (removed after
/// 2.x), `disable_pow = true` so submitted blocks need no PoW, and `enable_cookie_auth = false`
/// so clients authenticate with the rpcuser/rpcpassword the harness writes.
fn zebrad_toml(
    net_port: u16,
    rpc_port: u16,
    miner_address: &str,
    cache_dir: &str,
    nu6_3_height: u32,
) -> String {
    let nu6_2 = NU6_2_ACTIVATION_HEIGHT;
    let lockbox_addr = LOCKBOX_DISBURSEMENT_ADDR;
    let lockbox_amount = LOCKBOX_DISBURSEMENT_ZATS;
    // NU6.3 (ironwood) activation. Needs zebrad >= 6.2.2; older releases have no `"NU6.3"` key and
    // reject an unknown activation-height entry at startup.
    let nu6_3_line = format!("\"NU6.3\" = {nu6_3_height}\n");
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
# zecd's regtest network must match these heights (network::regtest).
[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = {nu6_2}
"NU6.2" = {nu6_2}
{nu6_3_line}
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

// =============================== funder (a released zecd) ===============================

/// A valid 24-word BIP-39 test mnemonic (the canonical all-zero-entropy vector). Regtest only - it
/// controls throwaway coinbase funds, never anything of value.
const FUNDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

/// The funder wallet's birthday. Height 2 is the lowest usable value: `zecd init --restore`
/// anchors the wallet on the tree state at `birthday - 1`, and genesis has none.
const FUNDER_BIRTHDAY: u32 = 2;

/// Derive the funder's transparent address at an explicit external `index` **offline** (`zecd
/// derive-address`): no chain, no wallet database, no daemon - which is what lets zebra mine to
/// the funder from genesis, with no seed blocks and no miner-swap restart.
///
/// Runs the **built** zecd (`zecd_bin`), not [`funder_bin`]: derivation is deterministic BIP-44
/// math, identical across versions, and the pinned release playing the funder may predate the
/// subcommand. [`start_funded_chain`] asserts the funder daemon agrees with this derivation once
/// its wallet exists.
///
/// Two indices matter. **Index 0** is the miner address: librustzcash exposes it at account
/// creation, so the funder's wallet credits coinbase mined there from the moment it exists -
/// without ever having to issue it. **Index 1** is what the fresh wallet's first
/// `getnewaddress "" "transparent"` issues (index 0 being already exposed, the issuance frontier
/// starts past it), which is what makes the daemon-vs-offline derivation check possible.
pub fn derive_funder_transparent_address(index: u32) -> Result<String> {
    let addr = derive_address_offline(FUNDER_MNEMONIC, "transparent", index)?;
    anyhow::ensure!(
        addr.starts_with("tm"),
        "derive-address printed {addr:?}, not a regtest t-address"
    );
    Ok(addr)
}

/// Derive a wallet address **offline** from `mnemonic` - no chain, no wallet database, no daemon -
/// via `zecd derive-address`. `address_type` takes `getnewaddress`'s `address_type` syntax
/// (`transparent`, `orchard`, `sapling,orchard`, ...) and `index` is the diversifier index (a
/// BIP-44 external child index for `transparent`).
///
/// This is what lets a test point zebra's `miner_address` at a wallet that does not exist yet, so
/// the chain is already in its final shape before the daemon ever scans a block. The alternative -
/// start the daemon, ask it for an address, then restart zebra to mine there - hands the daemon a
/// chain that is about to be rewound underneath it: zebra's non-finalized-state backup is written
/// asynchronously, so the restart drops the very blocks the daemon just scanned, and a young
/// wallet cannot rewind below its own birthday checkpoint.
pub fn derive_address_offline(mnemonic: &str, address_type: &str, index: u32) -> Result<String> {
    let out = Command::new(zecd_bin())
        // `--conf /dev/null` bypasses any zecd.toml a default datadir might hold: this derivation
        // has no deployment context, so nothing but the network flag may influence it.
        .args([
            "--conf",
            "/dev/null",
            "--regtest",
            "derive-address",
            "--mnemonic",
            "--address-type",
            address_type,
            "--index",
            &index.to_string(),
        ])
        .env("ZECD_MNEMONIC", mnemonic)
        .stdin(Stdio::null())
        .output()
        .context("spawn zecd derive-address")?;
    if !out.status.success() {
        bail!(
            "zecd derive-address failed ({}):\n{}",
            out.status,
            tail(&String::from_utf8_lossy(&out.stderr), 30)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Coinbase blocks the funder gets to actually spend. Every block mined once zebra points at the
/// funder pays it, so what really matters is how many are *mature* when we shield:
/// `FUNDER_COINBASES + MATURITY_TAIL - `[`COINBASE_MATURITY`] `= 30`. That has to stay under
/// `z_shieldcoinbase`'s default 50-UTXO limit, and to be worth more than any test spends (a
/// regtest coinbase is several ZEC; the whole tier spends a handful).
pub const FUNDER_COINBASES: u32 = 20;
/// Zcash's transparent-coinbase maturity: a coinbase output is unspendable until this many blocks
/// deep. `z_shieldcoinbase` filters immature UTXOs itself, so the funder may hold them - unlike the
/// previous funder, which had to be kept clear of them entirely.
pub const COINBASE_MATURITY: u32 = 100;
/// Blocks mined after the funder's coinbases so they clear [`COINBASE_MATURITY`], with slack.
pub const MATURITY_TAIL: u32 = COINBASE_MATURITY + 10;
/// Blocks mined after the shielding transaction confirms, so its note is comfortably spendable.
/// The funder runs at a confirmation depth of 1 (see [`write_funder_toml`]), so this is generous.
pub const SHIELD_CONFIRMATIONS: u32 = 6;
/// How many coinbase UTXOs one `z_shieldcoinbase` sweeps. Deliberately well under both zcashd's
/// default of 50 and the ~30 the funder has mature: a regtest coinbase is worth several ZEC, so ten
/// is far more than the whole tier spends, and a small input count keeps the shielding transaction
/// ordinary rather than the largest one the node will ever be asked to mine.
const SHIELD_UTXO_LIMIT: u32 = 10;
/// Upper bound on the blocks [`Funder::wait_until_mined`] will mine waiting for a transaction.
const MINE_UNTIL_CONFIRMED_BLOCKS: u32 = 20;

/// Locate the `zecd` binary that plays the **funder**: `$ZECD_FUNDER_BIN` when set (CI extracts it
/// from a digest-pinned `ghcr.io/zecrocks/zecd` release image), else the built binary.
///
/// Running a *released* zecd as the funder keeps the two sides of every funded test independent: a
/// regression on this branch cannot mask itself by being present in both the wallet under test and
/// the wallet paying it. It also makes the funded tier cross-version coverage - the last release
/// funds HEAD - which is the shape a real deployment upgrades through. Falling back to the built
/// binary keeps a bare `cargo test` working with no extra setup.
pub fn funder_bin() -> PathBuf {
    resolve_bin("ZECD_FUNDER_BIN").unwrap_or_else(zecd_bin)
}

/// A funding wallet: a second `zecd` daemon that owns the regtest chain's coinbase.
///
/// Regtest can't mine a coinbase straight into a shielded note the wallet under test would see, so
/// this is how funds get in: zebra mines transparent coinbase to the funder's t-address, it matures
/// (100 blocks), the funder sweeps it into a shielded note with `z_shieldcoinbase`, and then pays
/// the wallet under test. The funder talks straight to zebrad's JSON-RPC, so funding needs no
/// indexer or intermediary of any kind.
///
/// Bring-up: the funder's t-address is derived **offline** (`zecd derive-address`, see
/// [`derive_funder_transparent_address`]), so zebra mines to the funder from its very first
/// block and the wallet is created afterwards, against the already-grown chain:
///
/// ```text
/// let taddr = derive_funder_transparent_address(0)     // offline, before any chain exists
/// Zebrad::start_with_miner(node_bin, &taddr)
/// zebrad.generate_blocks(FUNDER_COINBASES + MATURITY)
/// let funder = Funder::init(zebrad.rpc_port)           // birthday 2, chain already live
/// funder.sync(&zebrad); let txid = funder.shield(); funder.wait_until_mined(&zebrad, &txid)
/// funder.send(target, zatoshis)
/// ```
///
/// No restart, so zebra's asynchronous non-finalized-state backup (which can drop just-mined
/// blocks across a restart) never comes into play. [`start_funded_chain`] is that whole sequence
/// in one call; every funded e2e opens with it.
pub struct Funder {
    child: Child,
    base_url: String,
    user: String,
    password: String,
    http: reqwest::Client,
    /// The wallet's own **Orchard-only** unified address: the `z_sendmany` source and the
    /// `z_shieldcoinbase` destination, so the funder's own funds stay in one pool.
    source_ua: String,
    /// A **multi-receiver** (Sapling + Orchard) unified address, which is what tests pay. Handing
    /// out more than one receiver keeps the outgoing-history reduction under test: zecd records the
    /// single receiver it actually paid, so a payee whose address carries only one receiver would
    /// make that reduction a no-op and the assertion vacuous.
    pay_to_ua: String,
    /// The wallet's first **issued** external transparent address (index 1 - index 0 is exposed
    /// at account creation and serves as the miner address; see
    /// [`derive_funder_transparent_address`]). Tests use it as an external transparent
    /// counterparty.
    taddr: String,
    _dir: tempfile::TempDir,
}

impl Funder {
    /// Initialise the funding wallet from [`FUNDER_MNEMONIC`] against a live regtest chain and
    /// bring its daemon up. The chain must already hold a block at `FUNDER_BIRTHDAY - 1` (init
    /// anchors the account on that tree state).
    pub async fn init(zebra_rpc_port: u16) -> Result<Funder> {
        let bin = funder_bin();
        if !bin.exists() {
            bail!(
                "funder zecd binary not found at {} - build it first \
                 (cargo build --release --bin zecd) or set $ZECD_FUNDER_BIN",
                bin.display()
            );
        }
        let dir = tempfile::tempdir().context("create funder dir")?;
        let cfg = FunderConfig {
            zebra_rpc_port,
            rpc_port: pick_port()?,
            health_port: pick_port()?,
            user: "funder",
            password: "funder",
        };

        write_funder_toml(dir.path(), &cfg)?;
        funder_init_with_retry(&bin, dir.path(), &cfg).await?;

        // Discard the daemon's logs unless ZECD_STDERR asks for them, exactly like `Zecd::start`
        // (both then interleave into the test output under `--nocapture`).
        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        let child = Command::new(&bin)
            .args([
                "--datadir",
                dir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("spawn funder zecd daemon")?;

        let mut funder = Funder {
            child,
            base_url: format!("http://127.0.0.1:{}/", cfg.rpc_port),
            user: cfg.user.to_string(),
            password: cfg.password.to_string(),
            http: reqwest::Client::new(),
            source_ua: String::new(),
            pay_to_ua: String::new(),
            taddr: String::new(),
            _dir: dir,
        };
        funder.wait_until_rpc_up().await?;

        // Resolve the addresses once. The transparent one is the wallet's first external index (a
        // fresh wallet, so the issuance frontier hasn't moved), which is what zebra will mine to;
        // the Orchard-only unified address is the funder's own source, and the Sapling+Orchard one
        // is what tests pay.
        funder.taddr = funder
            .call("getnewaddress", json!(["", "transparent"]))
            .await
            .context("funder getnewaddress transparent")?
            .as_str()
            .ok_or_else(|| anyhow!("funder getnewaddress transparent did not return a string"))?
            .to_string();
        funder.source_ua = funder
            .call("getnewaddress", json!([]))
            .await
            .context("funder getnewaddress")?
            .as_str()
            .ok_or_else(|| anyhow!("funder getnewaddress did not return a string"))?
            .to_string();
        funder.pay_to_ua = funder
            .call("getnewaddress", json!(["", "sapling,orchard"]))
            .await
            .context("funder getnewaddress (multi-receiver)")?
            .as_str()
            .ok_or_else(|| anyhow!("funder getnewaddress did not return a string"))?
            .to_string();
        Ok(funder)
    }

    /// The funder's first issued transparent address - a wallet-owned t-address tests pay when
    /// they need an external transparent counterparty. (Not the miner address; that is index 0,
    /// derived offline by [`start_funded_chain`] before this wallet existed.)
    pub fn transparent_address(&self) -> &str {
        &self.taddr
    }

    /// The funder's unified address: what tests pay when they send funds back. Carries **both** a
    /// Sapling and an Orchard receiver, so a payer's history has a reduction to actually perform.
    pub fn unified_address(&self) -> &str {
        &self.pay_to_ua
    }

    /// Wait until the funder has scanned up to `zebrad`'s current tip, so a balance or a send
    /// reflects everything mined so far. (zecd syncs continuously in the background, so unlike a
    /// CLI wallet there is nothing to drive here - only to wait for.)
    ///
    /// This polls `getblockchaininfo` rather than calling `waitforblockheight`: the funder is a
    /// pinned released binary, and the wait RPCs postdate every release it may be. Keep it that
    /// way until the pin moves past them.
    pub async fn sync(&self, zebrad: &Zebrad) -> Result<()> {
        let target = zebrad
            .rpc("getblockcount", json!([]))
            .await
            .context("funder sync: read zebra tip")?
            .as_u64()
            .ok_or_else(|| anyhow!("zebra getblockcount did not return a number"))?;
        let timeout = Duration::from_secs(300);
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(info) = self.call("getblockchaininfo", json!([])).await {
                if info.get("blocks").and_then(|b| b.as_u64()).unwrap_or(0) >= target {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("funder did not sync to height {target} within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Sweep [`SHIELD_UTXO_LIMIT`] of the funder's mature transparent coinbase into one shielded
    /// note (`z_shieldcoinbase "*" <own UA>`), returning the transaction id so the caller can wait
    /// for it to mine.
    ///
    /// The result is a *single* note with no change, so the caller must confirm it before the
    /// funder can spend it - [`start_funded_chain`] does that.
    pub async fn shield(&self) -> Result<String> {
        let res = self
            .call(
                "z_shieldcoinbase",
                json!(["*", self.source_ua, null, SHIELD_UTXO_LIMIT]),
            )
            .await
            .context("funder z_shieldcoinbase")?;
        let shielded = res
            .get("shieldingUTXOs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if shielded == 0 {
            bail!(
                "funder z_shieldcoinbase selected no coinbase UTXOs - the chain has not matured \
                 100 blocks past the funder's coinbases, or the funder has not scanned them yet: \
                 {res}"
            );
        }
        let opid = res
            .get("opid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("z_shieldcoinbase returned no opid: {res}"))?
            .to_string();
        let result = self.await_opid(&opid, Duration::from_secs(600)).await?;
        result["txid"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("z_shieldcoinbase operation carried no txid: {result}"))
    }

    /// Mine until `txid` has at least one confirmation, one block at a time.
    ///
    /// Mining a run of blocks in a single `generate` call makes the node's mempool see the tip jump
    /// by more than one block, which resets it ("switched best chain, skipped blocks") and can drop
    /// a transaction that was accepted moments earlier - so a broadcast is not enough on its own,
    /// and neither is mining a fixed number of blocks and hoping. Confirming block by block also
    /// turns "the funder ended up with no money" into an error that names the transaction that
    /// never mined.
    pub async fn wait_until_mined(&self, zebrad: &Zebrad, txid: &str) -> Result<()> {
        for _ in 0..MINE_UNTIL_CONFIRMED_BLOCKS {
            zebrad.generate_blocks(1).await.context("mine one block")?;
            self.sync(zebrad).await?;
            let tx = self.call("gettransaction", json!([txid])).await;
            if let Ok(tx) = tx {
                if tx
                    .get("confirmations")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(0)
                    >= 1
                {
                    return Ok(());
                }
            }
        }
        let mempool = self
            .call("getmempoolinfo", json!([]))
            .await
            .unwrap_or(Value::Null);
        bail!(
            "funder transaction {txid} did not mine within \
             {MINE_UNTIL_CONFIRMED_BLOCKS} blocks (node mempool: {mempool})"
        )
    }

    /// The funder's spendable balance in zatoshis, as `z_sendmany` would see it.
    async fn spendable_zats(&self) -> Result<u64> {
        let bal = self
            .call("getbalance", json!([]))
            .await
            .context("funder getbalance")?;
        let zec: f64 = bal
            .as_f64()
            .ok_or_else(|| anyhow!("funder getbalance did not return a number: {bal}"))?;
        Ok((zec * 1e8).round() as u64)
    }

    /// Send `zatoshis` to `to_address` (any address type: unified, Sapling, or a bare t-address).
    /// Waits for the transaction to be broadcast, not for it to mine.
    pub async fn send(&self, to_address: &str, zatoshis: u64) -> Result<()> {
        self.send_with_memo(to_address, zatoshis, None).await
    }

    /// Send `zatoshis` to `to_address`, optionally attaching a ZIP-302 **text** memo (hex-encoded
    /// here, since `z_sendmany` takes memos as hex). Used to exercise the recipient's receive-memo
    /// path: it must surface the memo on the received output.
    pub async fn send_with_memo(
        &self,
        to_address: &str,
        zatoshis: u64,
        memo: Option<&str>,
    ) -> Result<()> {
        let mut output = json!({ "address": to_address, "amount": zec_str(zatoshis) });
        if let Some(text) = memo {
            output["memo"] = json!(hex_encode(text.as_bytes()));
        }
        let opid = self
            .call("z_sendmany", json!([self.source_ua, [output]]))
            .await
            .with_context(|| format!("funder z_sendmany {zatoshis} zat to {to_address}"))?
            .as_str()
            .ok_or_else(|| anyhow!("z_sendmany did not return an opid"))?
            .to_string();
        self.await_opid(&opid, Duration::from_secs(600))
            .await
            .map(|_| ())
    }

    /// Drive an async operation (`z_sendmany` / `z_shieldcoinbase`) to completion and return its
    /// `result` object, failing with the operation's own error so a funding failure names its cause
    /// rather than surfacing later as an unexplained zero balance. Polls the **destructive**
    /// `z_getoperationresult`, which only ever reports a finished operation - so a returned entry
    /// is always terminal.
    ///
    /// A poll loop rather than `z_waitforoperation`, deliberately: the funder is a pinned released
    /// binary and that RPC postdates every release it may be. The zecd *under test* is HEAD, so
    /// tests waiting on their own daemon's operations should use `z_waitforoperation` instead.
    async fn await_opid(&self, opid: &str, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            let res = self
                .call("z_getoperationresult", json!([[opid]]))
                .await
                .context("funder z_getoperationresult")?;
            if let Some(entry) = res.as_array().and_then(|a| a.first()) {
                if entry.get("status").and_then(|s| s.as_str()) != Some("success") {
                    bail!("funder operation {opid} failed: {entry}");
                }
                return Ok(entry.get("result").cloned().unwrap_or(Value::Null));
            }
            if Instant::now() >= deadline {
                bail!("funder operation {opid} did not finish within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        zecd_rpc_call(
            &self.http,
            self.base_url.clone(),
            &self.user,
            &self.password,
            method,
            params,
        )
        .await
        .map_err(|e| anyhow!("funder {method}: {e}"))
    }

    async fn wait_until_rpc_up(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                bail!(
                    "funder zecd exited during startup ({status}); \
                     set ZECD_STDERR=1 to capture its logs"
                );
            }
            if self.call("uptime", json!([])).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("funder zecd RPC did not come up within 60s");
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

impl Drop for Funder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Bring up a regtest chain whose [`Funder`] holds spendable shielded funds - the opening move of
/// every funded e2e, in one call.
///
/// Returns the running node and the funded wallet. The funder's t-address is derived offline
/// before the node exists, so zebra mines to the funder from genesis: no seed blocks to a
/// throwaway address, no miner-swap restart, and no recovery logic for a restart dropping
/// just-mined blocks. From the first block on **every mined block pays the funder**, which is
/// harmless - `z_shieldcoinbase` filters immature coinbase itself, so accruing more never breaks
/// the shield.
pub async fn start_funded_chain(node_bin: &Path) -> Result<(Zebrad, Funder)> {
    // Mine to index 0: exposed at account creation, so the funder's wallet will credit these
    // coinbases without ever issuing the address. (Its first *issued* address is index 1.)
    let miner_taddr = derive_funder_transparent_address(0)
        .context("derive the funder's miner address offline")?;
    let zebrad = Zebrad::start_with_miner(node_bin, &miner_taddr)
        .await
        .context("start the regtest node mining to the funder")?;
    zebrad
        .generate_blocks(FUNDER_COINBASES + MATURITY_TAIL)
        .await
        .context("mine and mature the funder's coinbases")?;

    let funder = Funder::init(zebrad.rpc_port)
        .await
        .context("initialise the funding wallet")?;
    // Cross-version derivation check: the daemon (possibly a pinned older release) and the built
    // binary's offline derive-address must agree on the same mnemonic's addresses, or the
    // coinbase the node has been mining belongs to nobody. The daemon's first issued address is
    // index 1 - account creation already exposed index 0, so a fresh wallet's issuance frontier
    // starts past it (the same fact that makes index 0 safe to mine to above). If this fires,
    // either a derivation path changed across versions or librustzcash stopped exposing index 0
    // at creation; both need eyes, not a workaround.
    let expected_issued = derive_funder_transparent_address(1)
        .context("derive the funder's expected first issued address offline")?;
    anyhow::ensure!(
        funder.transparent_address() == expected_issued,
        "the funder daemon issued {} as its first transparent address, but offline \
         derive-address puts index 1 at {expected_issued} (and mined-to index 0 at {miner_taddr})",
        funder.transparent_address()
    );
    funder
        .sync(&zebrad)
        .await
        .context("funder sync (coinbase)")?;
    let shield_txid = funder
        .shield()
        .await
        .context("shield the funder's coinbase")?;
    funder
        .wait_until_mined(&zebrad, &shield_txid)
        .await
        .context("confirm the funder's shielding transaction")?;
    zebrad
        .generate_blocks(SHIELD_CONFIRMATIONS)
        .await
        .context("age the funder's shielded note")?;
    funder
        .sync(&zebrad)
        .await
        .context("funder sync (shielded)")?;

    // Fail here rather than in whichever test first tries to be paid: a funder with no spendable
    // balance surfaces downstream as an opaque -6 on a send, minutes and one indirection away from
    // whatever actually went wrong.
    anyhow::ensure!(
        funder.spendable_zats().await? > 0,
        "the funder shielded its coinbase in {shield_txid} but has no spendable balance"
    );
    Ok((zebrad, funder))
}

/// The node's current best-block height.
async fn zebra_block_count(zebrad: &Zebrad) -> Result<u64> {
    zebrad
        .rpc("getblockcount", json!([]))
        .await
        .context("getblockcount")?
        .as_u64()
        .ok_or_else(|| anyhow!("getblockcount did not return a number"))
}

/// The funder daemon's own endpoints and credentials - everything [`write_funder_toml`] needs that
/// isn't derived from the datadir.
struct FunderConfig {
    zebra_rpc_port: u16,
    rpc_port: u16,
    health_port: u16,
    user: &'static str,
    password: &'static str,
}

/// Write the funder's `zecd.toml`.
///
/// Deliberately **not** [`write_zecd_toml`]: that writer tracks the config surface of the branch
/// under test, and zecd rejects unknown config keys - so a knob added on this branch would break a
/// funder running a pinned older release. Only long-stable keys belong here.
///
/// The `[spend]` confirmation depths are load-bearing: `z_shieldcoinbase` produces a *single*
/// shielded output with no change, so at the default depths (3 trusted / 10 untrusted) a funder
/// paying two tests in a row would hit `-6` on the second send while its own change confirmed. The
/// harness owns the chain and mines every block itself, so there is no reorg risk to hedge against.
fn write_funder_toml(dir: &Path, cfg: &FunderConfig) -> Result<()> {
    let toml = format!(
        r#"network = "regtest"
datadir = "{datadir}"
default_wallet = "default"

[wallets.default]
dir = "{datadir}/default"

[pools]
# Both shielded pools are enabled but only Orchard is a default receiver, so the funder's own
# address (its spend source and shielding destination) stays single-pool while it can still hand
# out a multi-receiver address for tests to pay - see `Funder::pay_to_ua`.
enabled = ["sapling", "orchard"]
default_receivers = ["orchard"]
transparent = true

[backend]
server = "zebra://127.0.0.1:{zebra_rpc_port}"
connect_timeout_secs = 5
reconnect_base_secs = 1
reconnect_max_secs = 2

[rpc]
bind = "127.0.0.1"
port = {rpc_port}
user = "{user}"
password = "{password}"

[keys]
auto_unlock = true

[sync]
interval_secs = 2
rebroadcast_secs = 2

[health]
enabled = true
bind = "127.0.0.1"
port = {health_port}

[spend]
trusted_confirmations = 1
untrusted_confirmations = 1
"#,
        datadir = dir.display(),
        zebra_rpc_port = cfg.zebra_rpc_port,
        rpc_port = cfg.rpc_port,
        user = cfg.user,
        password = cfg.password,
        health_port = cfg.health_port,
    );
    std::fs::write(dir.join("zecd.toml"), toml)?;
    Ok(())
}

/// `zecd init --restore` the funder's wallet, retried while the upstream settles (the chain is
/// only a couple of blocks old and several stacks may be starting at once). The datadir is reset
/// between attempts so a partial init can't wedge the next one; the mnemonic goes in on stdin,
/// never on the command line.
async fn funder_init_with_retry(bin: &Path, dir: &Path, cfg: &FunderConfig) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match run_funder_init(bin, dir) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e.context("funder zecd init failed after retries"));
                }
                for entry in std::fs::read_dir(dir).context("read funder datadir for reset")? {
                    let path = entry?.path();
                    if path.is_dir() {
                        let _ = std::fs::remove_dir_all(&path);
                    } else {
                        let _ = std::fs::remove_file(&path);
                    }
                }
                write_funder_toml(dir, cfg)?;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

fn run_funder_init(bin: &Path, dir: &Path) -> Result<()> {
    let mut child = Command::new(bin)
        .args([
            "--datadir",
            dir.to_str().unwrap(),
            "--regtest",
            "init",
            "--restore",
            "--birthday",
            &FUNDER_BIRTHDAY.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn funder zecd init")?;
    {
        use std::io::Write as _;
        // Dropping the handle closes the pipe, so init sees EOF after the phrase.
        child
            .stdin
            .take()
            .context("funder init stdin not piped")?
            .write_all(format!("{FUNDER_MNEMONIC}\n").as_bytes())
            .context("write the mnemonic to funder zecd init")?;
    }
    let out = child
        .wait_with_output()
        .context("wait for funder zecd init")?;
    if !out.status.success() {
        bail!(
            "funder zecd init failed ({}):\n{}",
            out.status,
            tail(&String::from_utf8_lossy(&out.stderr), 30)
        );
    }
    Ok(())
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

/// Whether the extended ("big run") regtest tier is enabled: set `ZECD_REGTEST_EXTENDED=1`.
/// PR runs skip these tests (each spins a full zebra stack); the scheduled and
/// manually dispatched workflow runs set the variable.
pub fn extended_enabled() -> bool {
    std::env::var("ZECD_REGTEST_EXTENDED").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Whether the **stress** regtest tier is enabled: set `ZECD_REGTEST_STRESS=1`. Distinct from
/// (and heavier than) the extended tier - building thousands of notes and timing multi-minute
/// sends would blow up even the weekly extended run - so it is gated separately and driven only
/// by an explicit workflow dispatch and a rare (monthly) schedule, never on push/PR.
pub fn stress_enabled() -> bool {
    std::env::var("ZECD_REGTEST_STRESS").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// How many notes the stress test should build before measuring a send, from
/// `ZECD_STRESS_NOTE_COUNT` (default 256). The dispatch can dial this from a quick smoke (a few
/// hundred) to a heavy soak (thousands) without code changes.
pub fn stress_note_count() -> usize {
    std::env::var("ZECD_STRESS_NOTE_COUNT")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(256)
}

/// A running `zecd` daemon plus the HTTP client and credentials to drive it.
pub struct Zecd {
    child: Child,
    base_url: String,
    user: String,
    password: String,
    http: reqwest::Client,
    /// The default wallet's generated mnemonic, captured from `zecd init`'s stdout. `None`
    /// when the wallet was restored ([`ZecdConfig::restore_mnemonic`]) - a restore prints none.
    pub mnemonic: Option<String>,
    _datadir: tempfile::TempDir,
}

/// How `zecd` should reach the regtest chain (a local zebrad's JSON-RPC) and what RPC
/// port/creds to expose.
pub struct ZecdConfig {
    /// zebrad JSON-RPC port zecd connects to (`zebra://127.0.0.1:<port>`).
    pub zebra_rpc_port: u16,
    pub rpc_port: u16,
    pub rpc_user: String,
    pub rpc_password: String,
    /// `[sync] rebroadcast_secs` - tight by default so outage tests don't idle a minute.
    pub rebroadcast_secs: u64,
    /// Additional **spending** `[wallets.<name>]` entries beyond `default` (each gets its own
    /// `zecd init --wallet <name>` before the daemon starts). NB: zecd permits only ONE
    /// spending wallet, so configuring any of these alongside the spending `default` makes the
    /// daemon refuse to start - that refusal is what [`Zecd::start_expect_refusal`] asserts.
    pub extra_wallets: Vec<String>,
    /// Additional **watch-only** `[wallets.<name>]` entries, each created `--ufvk` from the
    /// `default` wallet's exported UFVK (a watch-only replica of the single spending wallet).
    /// Any number are allowed alongside the spending `default`.
    pub extra_watch_only_wallets: Vec<String>,
    /// Restore the default wallet from this mnemonic (`zecd init --restore`, phrase on stdin)
    /// instead of generating a fresh one.
    pub restore_mnemonic: Option<String>,
    /// Create the default wallet watch-only from this Unified Full Viewing Key
    /// (`zecd init --ufvk`) instead of a mnemonic.
    pub ufvk: Option<String>,
    /// `--birthday` for the restore/watch-only paths (a fresh init defaults near the tip on
    /// its own).
    pub birthday: Option<u32>,
    /// `[spend] cache_proving_key`: `Some(true/false)` writes the knob explicitly, `None`
    /// omits it (zecd defaults to `true`). The proving-key-cache benchmark runs one instance
    /// each way.
    pub cache_proving_key: Option<bool>,
    /// `[spend] pipeline_proving`: `Some(true/false)` writes the knob explicitly, `None` omits it
    /// (zecd defaults to `false`). The stress test runs with it on to exercise the off-actor
    /// proving pipeline (sync stays live during a send).
    pub pipeline_proving: Option<bool>,
    /// `[spend] orchard_action_limit`: `Some(n)` writes the cap (`0` disables it), `None` omits it
    /// (zecd defaults to 50). The stress test lifts the cap so its big fan-out/sweep sends aren't
    /// rejected.
    pub orchard_action_limit: Option<usize>,
    /// `[spend] privacy_policy`: `Some("AllowFullyTransparent")` etc. writes the knob explicitly,
    /// `None` omits it (zecd defaults to `AllowRevealedRecipients`). The fully-transparent spend
    /// e2e sets it to `AllowFullyTransparent`.
    pub privacy_policy: Option<String>,
    /// Optional `[pools]` section as `(enabled, default_receivers)`. `None` omits the section
    /// (the Orchard-only default). Used by the multi-pool (Sapling) e2e.
    pub pools: Option<(Vec<String>, Vec<String>)>,
    /// Write `[pools] transparent = true` so the wallet can hand out bare transparent addresses
    /// (`getnewaddress "" "transparent"`). Used by the transparent e2e. Emits a `[pools]` section
    /// even when `pools` is `None` (keeping the Orchard-only enabled default).
    pub transparent: bool,
    /// `[pools] transparent_gap_limit` - the external transparent gap limit, i.e. the
    /// stateless-restore scan depth. `None` omits it (zecd defaults to 20). Only meaningful with
    /// `transparent = true`. The transparent-gap restore e2e sets it small (a beyond-gap receive
    /// is missed) vs large (the same receive is recovered).
    pub transparent_gap_limit: Option<u32>,
    /// `[pools] transparent_initial_scan` - the initial scan depth (pre-expose + scan external
    /// indices `0..N` on startup, independent of the gap limit). `None` omits it (defaults to 0).
    /// The gap e2e uses it to prove a *small* gap plus a large initial scan still recovers a
    /// high-index receive.
    pub transparent_initial_scan: Option<u32>,
    /// `[pools] transparent_allow_beyond_recovery_window` - when `Some(false)`, `getnewaddress`
    /// fails closed once the recovery window is exhausted instead of issuing (warn-only) beyond it.
    /// `None` omits it (zecd defaults to `true`). Only meaningful with `transparent = true`.
    pub transparent_allow_beyond_recovery_window: Option<bool>,
    /// `[pools] transparent_gap_warn_threshold` - warn when fewer than this many in-window slots
    /// remain. `None` omits it (zecd defaults to 5). Only meaningful with `transparent = true`.
    pub transparent_gap_warn_threshold: Option<u32>,
    /// When `Some`, the spending `default` wallet is created passphrase-encrypted
    /// (`zecd init --encrypt`, passphrase supplied via `ZECD_WALLET_PASSPHRASE`): it starts
    /// locked and needs `walletpassphrase` before sending. `None` = unencrypted (identity model).
    pub encrypt_passphrase: Option<String>,
}

impl ZecdConfig {
    /// Test-friendly defaults: zecd points at the given zebrad JSON-RPC port, `user`/`pass`
    /// credentials, 2s rebroadcast, fast reconnect backoff (written by [`write_zecd_toml`]).
    pub fn new(zebra_rpc_port: u16, rpc_port: u16) -> ZecdConfig {
        ZecdConfig {
            zebra_rpc_port,
            rpc_port,
            rpc_user: "user".to_string(),
            rpc_password: "pass".to_string(),
            rebroadcast_secs: 2,
            extra_wallets: Vec::new(),
            extra_watch_only_wallets: Vec::new(),
            restore_mnemonic: None,
            ufvk: None,
            birthday: None,
            cache_proving_key: None,
            pipeline_proving: None,
            orchard_action_limit: None,
            privacy_policy: None,
            pools: None,
            transparent: false,
            transparent_gap_limit: None,
            transparent_initial_scan: None,
            transparent_allow_beyond_recovery_window: None,
            transparent_gap_warn_threshold: None,
            encrypt_passphrase: None,
        }
    }

    /// The `[health]` port (`/healthz`, `/readyz`, `/status`) the daemon is configured with -
    /// [`write_zecd_toml`]'s convention is the RPC port + 1.
    pub fn health_port(&self) -> u16 {
        self.rpc_port + 1
    }
}

impl Zecd {
    /// Write a regtest `zecd.toml`, run `zecd init` (retried while zebra catches up to the
    /// chain tip), then spawn the daemon. Returns once the RPC is up; call
    /// [`Zecd::wait_until_synced`] to wait for the scan to reach the tip.
    pub async fn start(cfg: &ZecdConfig) -> Result<Zecd> {
        let (datadir, mnemonic) = Self::prepare_datadir(cfg).await?;

        // Set ZECD_STDERR (to any value) to stream the daemon's logs into the test output
        // (use with `--nocapture`); otherwise discard them. The daemon inherits RUST_LOG from
        // the environment, so `RUST_LOG=zecd=debug,info ZECD_STDERR=1` gives a full sync/rewind
        // trace in CI. Mirrors the ZEBRAD_STDERR hook above.
        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        let child = Command::new(zecd_bin())
            .args([
                "--datadir",
                datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("spawn zecd daemon")?;

        let zecd = Zecd {
            child,
            base_url: format!("http://127.0.0.1:{}/", cfg.rpc_port),
            user: cfg.rpc_user.clone(),
            password: cfg.rpc_password.clone(),
            http: reqwest::Client::new(),
            mnemonic,
            _datadir: datadir,
        };

        zecd.wait_until_rpc_up().await?;
        Ok(zecd)
    }

    /// Set up a datadir with the spending `default` wallet, then attempt `zecd init --wallet
    /// <name>` for a **second spending** wallet, expecting zecd's init-time guard to refuse it
    /// (zecd allows only one spending wallet). `cfg.extra_wallets` must list `name` so the
    /// config the guard scans contains both wallets. Returns the refusal's stderr; errors if
    /// the second init unexpectedly succeeded.
    pub async fn init_second_spending_expect_refusal(
        cfg: &ZecdConfig,
        name: &str,
    ) -> Result<String> {
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
        init_default_with_retry(&bin, datadir.path(), cfg).await?;

        // The guard runs before any network I/O, so this fails fast offline.
        let out = Command::new(&bin)
            .args([
                "--datadir",
                datadir.path().to_str().unwrap(),
                "--regtest",
                "init",
                "--wallet",
                name,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("spawn second zecd init")?;
        anyhow::ensure!(
            !out.status.success(),
            "zecd init of a second spending wallet was expected to fail but succeeded"
        );
        Ok(String::from_utf8_lossy(&out.stderr).into_owned())
    }

    /// Prepare a datadir: write `zecd.toml`, init the `default` wallet (retried while the node
    /// warms up), then init any watch-only replicas. (Only one spending wallet is
    /// permitted, so extra *spending* wallets are never initialised here.)
    async fn prepare_datadir(cfg: &ZecdConfig) -> Result<(tempfile::TempDir, Option<String>)> {
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
        // Every regtest is a free assertion that `zecd config check` agrees with the daemon:
        // this exact file is about to be handed to a zecd that must start on it, so a check
        // that rejects it (or a daemon that refuses a file the check passed) is a real
        // disagreement between the two - on a production-shaped config rather than a fixture,
        // across both backends and every tier.
        assert_config_check_passes(&bin, datadir.path())?;
        let mnemonic = init_default_with_retry(&bin, datadir.path(), cfg).await?;

        // Watch-only replicas derive from the default wallet's exported UFVK (read straight from
        // the on-disk DB; no running daemon needed). `init --ufvk` fetches GetTreeState(birthday-1),
        // so use the lowest height with a real block (2) when no birthday is configured.
        if !cfg.extra_watch_only_wallets.is_empty() {
            let ufvk = export_ufvk_from_datadir(datadir.path(), "default")
                .context("export default UFVK for watch-only replicas")?;
            let birthday = cfg.birthday.unwrap_or(2);
            for name in &cfg.extra_watch_only_wallets {
                run_zecd_init_watch_only(&bin, datadir.path(), name, &ufvk, Some(birthday))
                    .with_context(|| format!("init watch-only wallet '{name}'"))?;
            }
        }

        Ok((datadir, mnemonic))
    }

    /// Run `zecd export-ufvk` against this daemon's datadir and return the printed Unified
    /// Full Viewing Key (the last stdout line). Safe while the daemon runs: the command only
    /// reads the wallet DB.
    pub fn export_ufvk(&self, wallet: &str) -> Result<String> {
        export_ufvk_from_datadir(self._datadir.path(), wallet)
    }

    /// The daemon's data directory (owned by this handle; deleted when it drops). Lets tests
    /// inspect and tamper with on-disk wallet state (`keys.toml`, `data.sqlite`) around
    /// restarts, e.g. the account-to-keys binding e2e.
    pub fn datadir(&self) -> &Path {
        self._datadir.path()
    }

    /// Gracefully stop the daemon (the `stop` RPC, falling back to kill), keeping the data
    /// directory intact so a test can modify on-disk state and relaunch against it with
    /// [`Zecd::respawn`] or [`Zecd::respawn_expect_startup_failure`].
    pub async fn stop_keeping_datadir(&mut self) -> Result<()> {
        let _ = self.call("stop", json!([])).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Ok(());
                }
            }
        }
    }

    /// Relaunch the daemon on the kept data directory (after [`Zecd::stop_keeping_datadir`])
    /// with the same config, and wait for the RPC to come back up.
    pub async fn respawn(&mut self) -> Result<()> {
        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        self.child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("respawn zecd")?;
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    /// Relaunch the daemon on the kept data directory and expect startup to FAIL: wait for
    /// the process to exit nonzero and return its stderr (for asserting on the refusal
    /// message). Errors if the daemon comes up or exits cleanly. Used by the binding e2e:
    /// a swapped `data.sqlite` must refuse to serve.
    pub async fn respawn_expect_startup_failure(&mut self) -> Result<String> {
        let mut child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("respawn zecd expecting a startup failure")?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        use std::io::Read as _;
                        let _ = pipe.read_to_string(&mut stderr);
                    }
                    anyhow::ensure!(
                        !status.success(),
                        "zecd was expected to refuse startup but exited cleanly; stderr:\n\
                         {stderr}"
                    );
                    return Ok(stderr);
                }
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("zecd was expected to refuse startup but is still running after 60s");
                }
                Err(e) => return Err(anyhow!("waiting for zecd to exit: {e}")),
            }
        }
    }

    /// Stop the daemon, delete every wallet's `data.sqlite` (and the compact-block cache), and
    /// restart against the *same* data directory - simulating a disposable/empty data directory
    /// next to a preserved `keys.toml`. Exercises the Phase-1 bootstrap rebuild path on a real
    /// chain. `keys.toml`, the age identity, and `zecd.toml` are left untouched, so the daemon
    /// rebuilds the account from `keys.toml` (immediately for an auto-unlock wallet, at the first
    /// `walletpassphrase` for an encrypted one). The RPC port/credentials are unchanged.
    pub async fn restart_wiping_data_db(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();

        // Remove each wallet subdirectory's derived state, keeping its keys.toml.
        for entry in std::fs::read_dir(self._datadir.path()).context("read datadir for wipe")? {
            let path = entry.context("datadir entry")?.path();
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(path.join("blocks"));
                for name in ["data.sqlite", "data.sqlite-wal", "data.sqlite-shm"] {
                    let _ = std::fs::remove_file(path.join(name));
                }
            }
        }

        let (out, err) = if std::env::var_os("ZECD_STDERR").is_some() {
            (Stdio::inherit(), Stdio::inherit())
        } else {
            (Stdio::null(), Stdio::null())
        };
        let child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(out)
            .stderr(err)
            .spawn()
            .context("respawn zecd on the wiped data directory")?;
        self.child = child;
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    /// Graceful shutdown via the `stop` RPC: asserts bitcoind's reply shape ("zecd stopping"),
    /// then waits for the process to exit cleanly (status 0).
    pub async fn shutdown(mut self) -> Result<()> {
        let reply = self
            .call("stop", json!([]))
            .await
            .map_err(|e| anyhow!("stop RPC failed: {e}"))?;
        anyhow::ensure!(
            reply == json!("zecd stopping"),
            "unexpected stop reply: {reply}"
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    anyhow::ensure!(status.success(), "zecd exited with {status} after stop");
                    return Ok(());
                }
                Ok(None) => {
                    anyhow::ensure!(
                        Instant::now() < deadline,
                        "zecd did not exit within 30s of the stop RPC"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => return Err(anyhow!("waiting for zecd to exit: {e}")),
            }
        }
    }

    /// Gracefully stop the daemon (via the `stop` RPC) and relaunch it against the *same*
    /// datadir/wallet with a (possibly different) config - e.g. flipping
    /// `[spend] cache_proving_key`. The wallet DB, keys, and funds persist across the restart;
    /// `cfg` must keep the same RPC port so this handle's `base_url` stays valid. Used by the
    /// proving-key-cache benchmark to measure both paths on one funded wallet.
    pub async fn restart(&mut self, cfg: &ZecdConfig) -> Result<()> {
        let _ = self.call("stop", json!([])).await;
        let deadline = Instant::now() + Duration::from_secs(30);
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
        write_zecd_toml(self._datadir.path(), cfg).context("rewrite zecd.toml for restart")?;
        self.child = Command::new(zecd_bin())
            .args([
                "--datadir",
                self._datadir.path().to_str().unwrap(),
                "--regtest",
                "run",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("respawn zecd")?;
        self.base_url = format!("http://127.0.0.1:{}/", cfg.rpc_port);
        self.user = cfg.rpc_user.clone();
        self.password = cfg.rpc_password.clone();
        self.wait_until_rpc_up().await?;
        Ok(())
    }

    /// Issue a JSON-RPC call, returning the `result` on success or an error carrying the
    /// Bitcoin Core error `code` (so tests can assert e.g. `-6` for insufficient funds).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.call_at(self.base_url.clone(), method, params).await
    }

    /// Issue a JSON-RPC call against a named wallet's `/wallet/<name>` endpoint (multiwallet
    /// routing; the bare [`Zecd::call`] serves the default wallet).
    pub async fn call_wallet(
        &self,
        wallet: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, RpcError> {
        self.call_at(format!("{}wallet/{wallet}", self.base_url), method, params)
            .await
    }

    async fn call_at(&self, url: String, method: &str, params: Value) -> Result<Value, RpcError> {
        zecd_rpc_call(&self.http, url, &self.user, &self.password, method, params).await
    }

    /// The current best-block height as seen by zecd (`getblockcount`).
    pub async fn block_count(&self) -> Result<u64> {
        self.call("getblockcount", json!([]))
            .await
            .map_err(|e| anyhow!("{e}"))?
            .as_u64()
            .ok_or_else(|| anyhow!("getblockcount did not return a number"))
    }

    /// Block until zecd has **scanned** up to the node's current tip.
    ///
    /// Reach for this before asserting on confirmed state after mining. Polling a balance instead
    /// is not equivalent: a transparent receive is visible in `getbalance` from the mempool while
    /// still unmined, so a balance wait can be satisfied before the funding block has been scanned,
    /// leaving `listunspent` (minconf 1) empty and the assertion racing the scan.
    pub async fn wait_until_synced_to_node(
        &self,
        zebrad: &Zebrad,
        timeout: Duration,
    ) -> Result<()> {
        let target = zebra_block_count(zebrad).await?;
        self.wait_until_synced(target, timeout).await
    }

    /// Block until zecd has *scanned* to `target` - `getblockchaininfo.blocks`, the height at
    /// which balances and history are accurate.
    ///
    /// This asks the daemon the question directly (`waitforblockheight`) instead of polling a
    /// proxy for it. Never substitute a balance poll: the mempool stream credits an incoming
    /// payment at 0 confirmations, so a balance is satisfied *before* the confirming block is
    /// scanned - which is how a test can go on to read a height-dependent field (confirmations,
    /// `listsinceblock`, a `blockhash`) that the wallet has not written yet.
    ///
    /// The server-side wait is capped per call so a hung daemon still surfaces as this
    /// function's own timeout rather than an indefinite block.
    pub async fn wait_until_synced(&self, target: u64, timeout: Duration) -> Result<()> {
        const MAX_SERVER_WAIT: Duration = Duration::from_secs(5);
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("zecd did not sync to height {target} within {timeout:?}");
            }
            // Never 0: that is `waitforblockheight`'s "wait indefinitely".
            let wait_ms = remaining.min(MAX_SERVER_WAIT).as_millis().max(1) as u64;
            match self
                .call("waitforblockheight", json!([target, wait_ms]))
                .await
            {
                Ok(v) => {
                    if v.get("height").and_then(|h| h.as_u64()).unwrap_or(0) >= target {
                        return Ok(());
                    }
                }
                // The daemon may not be serving yet (restart tests reuse this); retry until the
                // deadline rather than failing on the first refused connection.
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
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

/// JSON-RPC 1.0 call to a `zecd` (bitcoind's envelope, HTTP Basic auth), shared by the daemon
/// under test ([`Zecd::call`]) and the [`Funder`]'s own daemon.
async fn zecd_rpc_call(
    http: &reqwest::Client,
    url: String,
    user: &str,
    password: &str,
    method: &str,
    params: Value,
) -> Result<Value, RpcError> {
    let body = json!({ "jsonrpc": "1.0", "id": "harness", "method": method, "params": params });
    let resp = http
        .post(url)
        .basic_auth(user, Some(password))
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

/// Format zatoshis as an 8-dp ZEC decimal string, the amount shape zecd's send RPCs take.
pub fn zec_str(zat: u64) -> String {
    format!("{}.{:08}", zat / 100_000_000, zat % 100_000_000)
}

/// Lowercase hex, for the `z_sendmany` memo field (a text memo goes on the wire hex-encoded).
/// A four-line helper rather than a `hex` dependency the harness needs nowhere else.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

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

/// Run `zecd init` for one wallet, returning the generated mnemonic (printed on stdout by a
/// fresh init; `None` on the restore path, which prints none). The restore path applies to
/// the default wallet only: the phrase from [`ZecdConfig::restore_mnemonic`] is fed on stdin
/// and `--birthday` is passed when set.
fn run_zecd_init(
    bin: &Path,
    datadir: &Path,
    wallet: &str,
    cfg: &ZecdConfig,
) -> Result<Option<String>> {
    let mut args: Vec<String> = vec![
        "--datadir".into(),
        datadir.to_str().unwrap().into(),
        "--regtest".into(),
        "init".into(),
        "--wallet".into(),
        wallet.into(),
    ];
    let restore = (wallet == "default")
        .then(|| cfg.restore_mnemonic.clone())
        .flatten();
    let ufvk = (wallet == "default").then(|| cfg.ufvk.clone()).flatten();
    if restore.is_some() {
        args.push("--restore".into());
    }
    if let Some(key) = &ufvk {
        args.push("--ufvk".into());
        args.push(key.clone());
    }
    if restore.is_some() || ufvk.is_some() {
        if let Some(b) = cfg.birthday {
            args.push("--birthday".into());
            args.push(b.to_string());
        }
    }
    // The spending `default` wallet may be created passphrase-encrypted; the passphrase is
    // passed out-of-band via `ZECD_WALLET_PASSPHRASE` (never on the command line). `--encrypt`
    // is incompatible with `--ufvk`, so it only applies to the seed-bearing default wallet.
    let encrypt = (wallet == "default" && ufvk.is_none())
        .then(|| cfg.encrypt_passphrase.clone())
        .flatten();
    if encrypt.is_some() {
        args.push("--encrypt".into());
    }
    let mut command = Command::new(bin);
    command
        .args(&args)
        .stdin(if restore.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(pass) = &encrypt {
        command.env("ZECD_WALLET_PASSPHRASE", pass);
    }
    let mut child = command.spawn().context("spawn zecd init")?;
    if let Some(phrase) = &restore {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(format!("{phrase}\n").as_bytes())
            .context("write the mnemonic to zecd init")?;
    }
    let out = child.wait_with_output().context("wait for zecd init")?;
    if !out.status.success() {
        bail!(
            "zecd init --wallet {wallet} failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let phrase = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((!phrase.is_empty()).then_some(phrase))
}

/// Init the `default` wallet, retried while the node catches up to the chain tip. Just after
/// launch zebrad may still be committing blocks, so `zecd init` (which contacts it for the
/// chain tip and tree state) is retried, resetting the datadir between
/// attempts so a partial init can't wedge the next one. Returns the generated mnemonic.
async fn init_default_with_retry(
    bin: &Path,
    datadir: &Path,
    cfg: &ZecdConfig,
) -> Result<Option<String>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match run_zecd_init(bin, datadir, "default", cfg) {
            Ok(mnemonic) => return Ok(mnemonic),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e.context("zecd init failed after retries"));
                }
                reset_datadir(datadir, cfg)?;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Run `zecd init --wallet <wallet> --ufvk <ufvk>` to create a watch-only wallet (no spending
/// material). `birthday` sets the scan start (`init --ufvk` fetches GetTreeState(birthday-1),
/// so genesis/height-1 are rejected - pass ≥ 2).
fn run_zecd_init_watch_only(
    bin: &Path,
    datadir: &Path,
    wallet: &str,
    ufvk: &str,
    birthday: Option<u32>,
) -> Result<()> {
    let mut args: Vec<String> = vec![
        "--datadir".into(),
        datadir.to_str().unwrap().into(),
        "--regtest".into(),
        "init".into(),
        "--wallet".into(),
        wallet.into(),
        "--ufvk".into(),
        ufvk.into(),
    ];
    if let Some(b) = birthday {
        args.push("--birthday".into());
        args.push(b.to_string());
    }
    let out = Command::new(bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn zecd init --ufvk")?
        .wait_with_output()
        .context("wait for zecd init --ufvk")?;
    if !out.status.success() {
        bail!(
            "zecd init --wallet {wallet} --ufvk failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Run `zecd config check` against a datadir's freshly written `zecd.toml` and require it to
/// pass. Offline and read-only (it takes no datadir lock and writes nothing), so it costs one
/// process spawn.
///
/// Warnings are expected here and do not fail the check - at this point no wallet has been
/// initialised yet, which the command reports as exactly that. `--strict` would turn that
/// normal state into a failure.
fn assert_config_check_passes(bin: &Path, datadir: &Path) -> Result<()> {
    let out = Command::new(bin)
        .args([
            "config",
            "check",
            "--conf",
            datadir.join("zecd.toml").to_str().unwrap(),
        ])
        .output()
        .context("spawn zecd config check")?;
    if !out.status.success() {
        bail!(
            "zecd config check rejected the config this test is about to run zecd on ({}):\n{}{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Run `zecd export-ufvk --wallet <wallet>` against a datadir (reads the wallet DB directly; no
/// running daemon required) and return the printed Unified Full Viewing Key (the last non-empty
/// stdout line).
fn export_ufvk_from_datadir(datadir: &Path, wallet: &str) -> Result<String> {
    let out = Command::new(zecd_bin())
        .args([
            "--datadir",
            datadir.to_str().unwrap(),
            "--regtest",
            "export-ufvk",
            "--wallet",
            wallet,
        ])
        .output()
        .context("spawn zecd export-ufvk")?;
    if !out.status.success() {
        bail!(
            "zecd export-ufvk failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("export-ufvk printed nothing on stdout"))
}

fn write_zecd_toml(datadir: &Path, cfg: &ZecdConfig) -> Result<()> {
    // zecd is zebra-only: the single upstream is a local zebrad JSON-RPC endpoint.
    let server = format!("zebra://127.0.0.1:{}", cfg.zebra_rpc_port);
    // Optional `[spend]` knobs: `cache_proving_key` (the proving-key-cache benchmark) and
    // `privacy_policy` (the fully-transparent spend e2e). Emit the section if either is set.
    let spend_section = if cfg.cache_proving_key.is_some()
        || cfg.pipeline_proving.is_some()
        || cfg.orchard_action_limit.is_some()
        || cfg.privacy_policy.is_some()
    {
        let mut s = String::from("\n[spend]\n");
        if let Some(b) = cfg.cache_proving_key {
            s.push_str(&format!("cache_proving_key = {b}\n"));
        }
        if let Some(b) = cfg.pipeline_proving {
            s.push_str(&format!("pipeline_proving = {b}\n"));
        }
        if let Some(n) = cfg.orchard_action_limit {
            s.push_str(&format!("orchard_action_limit = {n}\n"));
        }
        if let Some(p) = &cfg.privacy_policy {
            s.push_str(&format!("privacy_policy = \"{p}\"\n"));
        }
        s
    } else {
        String::new()
    };
    // The default wallet plus any extra `[wallets.<name>]` entries (multiwallet tests).
    let mut wallets = format!(
        "[wallets.default]\ndir = \"{}/default\"\n",
        datadir.display()
    );
    for name in cfg
        .extra_wallets
        .iter()
        .chain(&cfg.extra_watch_only_wallets)
    {
        wallets.push_str(&format!(
            "\n[wallets.{name}]\ndir = \"{}/{name}\"\n",
            datadir.display()
        ));
    }
    // Optional [pools] section (multi-pool / Sapling e2e, and/or transparent receiving); omitted
    // entirely -> Orchard-only, no transparent.
    let pools = if cfg.pools.is_some() || cfg.transparent {
        let mut s = String::from("\n[pools]\n");
        if let Some((enabled, receivers)) = &cfg.pools {
            let list = |v: &[String]| {
                v.iter()
                    .map(|p| format!("\"{p}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            s.push_str(&format!(
                "enabled = [{}]\ndefault_receivers = [{}]\n",
                list(enabled),
                list(receivers)
            ));
        }
        if cfg.transparent {
            s.push_str("transparent = true\n");
            if let Some(g) = cfg.transparent_gap_limit {
                s.push_str(&format!("transparent_gap_limit = {g}\n"));
            }
            if let Some(n) = cfg.transparent_initial_scan {
                s.push_str(&format!("transparent_initial_scan = {n}\n"));
            }
            if let Some(a) = cfg.transparent_allow_beyond_recovery_window {
                s.push_str(&format!("transparent_allow_beyond_recovery_window = {a}\n"));
            }
            if let Some(t) = cfg.transparent_gap_warn_threshold {
                s.push_str(&format!("transparent_gap_warn_threshold = {t}\n"));
            }
        }
        s
    } else {
        String::new()
    };
    wallets.push_str(&pools);
    // Fast reconnect backoff (1..2s) so outage-recovery tests converge quickly.
    let toml = format!(
        r#"network = "regtest"
datadir = "{datadir}"
default_wallet = "default"

{wallets}
[backend]
server = "{server}"
connect_timeout_secs = 5
reconnect_base_secs = 1
reconnect_max_secs = 2

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
{spend_section}"#,
        datadir = datadir.display(),
        wallets = wallets,
        server = server,
        rpc_port = cfg.rpc_port,
        user = cfg.rpc_user,
        password = cfg.rpc_password,
        rebroadcast = cfg.rebroadcast_secs,
        health_port = cfg.health_port(),
        spend_section = spend_section,
    );
    std::fs::write(datadir.join("zecd.toml"), toml)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_port_stays_below_the_ephemeral_floor_and_binds() {
        let mut last = None;
        for _ in 0..8 {
            let port = pick_port().expect("pick a port");
            assert!(
                (20000..32000).contains(&port),
                "picked port {port} outside the non-ephemeral probe range"
            );
            assert_ne!(Some(port), last, "cursor must advance between picks");
            let _hold = TcpListener::bind(("127.0.0.1", port)).expect("picked port is bindable");
            last = Some(port);
        }
    }

    /// Concurrent callers must never be handed the same port. This is the shape that broke the
    /// tier when the harness first ran a binary's two tests side by side: both stacks got the
    /// same port from `pick_port`, and the second daemon to bind it died with `Address already
    /// in use`. Ports are held (not released) until every thread has picked, which is what the
    /// real callers do - they hand the port to a daemon that binds it moments later.
    #[test]
    fn concurrent_picks_never_collide() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 16;
        let picked = std::sync::Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    let mut held = Vec::new();
                    for _ in 0..PER_THREAD {
                        let port = pick_port().expect("pick a port");
                        held.push((port, TcpListener::bind(("127.0.0.1", port))));
                    }
                    picked.lock().unwrap().extend(held);
                });
            }
        });
        let picked = picked.into_inner().unwrap();
        assert_eq!(picked.len(), THREADS * PER_THREAD);
        for (port, bound) in &picked {
            assert!(bound.is_ok(), "port {port} was handed out twice");
        }
        let unique: std::collections::HashSet<u16> = picked.iter().map(|(p, _)| *p).collect();
        assert_eq!(unique.len(), picked.len(), "duplicate ports handed out");
    }

    #[test]
    fn port_window_defaults_to_the_whole_non_ephemeral_range() {
        // No env set in this process (the parallel driver sets it per test *binary*, and the unit
        // tests run in the lib target, which the driver never slices).
        let (lo, span) = port_window();
        assert_eq!((lo, span), (DEFAULT_PORT_LO, DEFAULT_PORT_SPAN));
        assert!(u32::from(lo) + u32::from(span) <= 32768);
    }
}
