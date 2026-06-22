//! Daemon wiring for the `zecd` binary: tracing init, wallet-actor spawning, the health and
//! RPC servers, and graceful shutdown.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::backend;
use crate::config::{self, AppConfig};
use crate::health;
use crate::server;
use crate::state::AppState;
use crate::wallet::actor::{self, ActorConfig};
use crate::wallet::binding;
use crate::wallet::store::WalletStore;
use crate::wallet::WalletRegistry;

/// Initialize tracing. The filter defaults to `[log] level` and is overridden by `RUST_LOG`;
/// `[log] format = "json"` emits structured logs for cloud-native log aggregation.
pub fn init_tracing(log: &config::LogConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log.level));
    // `zcash_client_sqlite` runs its schema migrations through `schemerz`, which logs each one at
    // INFO via the `log` crate (bridged into tracing). On a fresh datadir that's ~60 lines of
    // "Applying migration <uuid>" noise at startup. Quiet that target to WARN by default so the
    // migration chatter stays out of the way - unless the operator explicitly scoped `schemerz`
    // in `RUST_LOG`, in which case their directive wins.
    let filter = if std::env::var("RUST_LOG").is_ok_and(|v| v.contains("schemerz")) {
        filter
    } else {
        filter.add_directive("schemerz=warn".parse().expect("static directive parses"))
    };
    // Log to stderr, not stdout: the `init`/`export-ufvk` CLI subcommands print machine-readable
    // output (the mnemonic, a UFVK) to stdout, and a log line on stdout would corrupt it.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if log.format.eq_ignore_ascii_case("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    let prog = "zecd";
    // Single-instance guard: take the exclusive datadir lock before opening any wallet, and hold
    // it for the whole daemon lifetime (until `run` returns). A second zecd on the same datadir
    // would corrupt the wallet DB; this makes it refuse to start instead. See `crate::lock`.
    let _datadir_lock = crate::lock::lock_datadir(&config.datadir)?;
    // The example/deploy configs ship with a placeholder RPC password; on mainnet that is
    // spend authority, so refuse to start until it has been changed.
    if matches!(config.network, crate::network::ZNetwork::Main)
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
    actor::install_panic_hook();
    let config = Arc::new(config);
    let auth = server::auth::Authenticator::from_config(&config.rpc)?;
    log_auth_mode(&config.rpc, rpcpassword_on_cli(std::env::args_os()));

    // Shutdown broadcast: `true` is sent on Ctrl-C / `stop`. Created before the actors so
    // each one carries a receiver and can stop its sync loop between batches.
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut registry = WalletRegistry::new(config.default_wallet.clone());
    let mut actor_tasks = Vec::new();
    // Build the Orchard proving/verifying keys once (they're wallet-independent) and share them
    // across every actor, so each send reuses the cached key instead of rebuilding it per
    // transaction. Built off the async runtime; on by default (`[spend] cache_proving_key`).
    let orchard_keys = if config.spend.cache_proving_key {
        info!("building Orchard proving key (cached for all sends)");
        Some(Arc::new(
            tokio::task::spawn_blocking(actor::ProvingKeyCache::build)
                .await
                .map_err(|e| anyhow::anyhow!("failed to build Orchard proving key: {e}"))?,
        ))
    } else {
        None
    };
    // zecd permits at most one wallet with spending keys; watch-only (UFVK) wallets may be
    // loaded without limit. Record each opened wallet's watch-only flag so the invariant can
    // be enforced once every wallet has been spawned (the flag is only known after the actor
    // reads the account from the wallet DB).
    let mut loaded: Vec<(String, bool)> = Vec::new();
    for (name, entry) in &config.wallets {
        let keys_path = entry.keys_path();
        if !WalletStore::exists(&keys_path) {
            warn!(
                "wallet '{}' is not initialized ({} missing); skipping (run `{prog} init --wallet {}`)",
                name,
                keys_path.display(),
                name
            );
            continue;
        }
        let mut server = backend::resolve(&config.backend.server, config.network)?;
        backend::apply_zebra_auth(&mut server, &config.zebra.auth());
        backend::apply_cleartext_policy(
            &mut server,
            crate::chain::zebra::CleartextPolicy {
                rfc1918_is_local: config.backend.rfc1918_is_local,
                allow_remote_cleartext: config.backend.allow_remote_cleartext,
            },
        );
        let actor_cfg = ActorConfig {
            name: name.clone(),
            network: config.network,
            wallet_dir: entry.dir.clone(),
            keys_path: keys_path.clone(),
            server,
            sync_interval: Duration::from_secs(config.sync.interval_secs),
            rebroadcast_interval: Duration::from_secs(config.sync.rebroadcast_secs),
            connect_timeout: Duration::from_secs(config.backend.connect_timeout_secs),
            reconnect_base: Duration::from_secs(config.backend.reconnect_base_secs),
            reconnect_max: Duration::from_secs(config.backend.reconnect_max_secs),
            age_identity: config.keys.age_identity.clone(),
            auto_unlock: config.keys.auto_unlock,
            bootstrap: config.keys.bootstrap_from_keys,
            // Validated at config load; re-derive here rather than carrying a second copy.
            confirmations_policy: config.spend.confirmations_policy()?,
            orchard_action_limit: config.spend.orchard_action_limit,
            orchard_keys: orchard_keys.clone(),
            pipeline_proving: config.spend.pipeline_proving,
            enabled_pools: entry.pools.clone(),
            default_receivers: entry.default_receivers.clone(),
            transparent_enabled: entry.transparent_enabled,
            transparent_default: entry.transparent_default,
            transparent_gap_limit: entry.transparent_gap_limit,
            transparent_initial_scan: entry.transparent_initial_scan,
            shutdown: shutdown_tx.subscribe(),
        };
        match actor::spawn(actor_cfg).await {
            Ok((handle, task)) => {
                let watch_only = handle.status().watch_only;
                info!(
                    "loaded wallet '{}'{}",
                    name,
                    if watch_only { " (watch-only)" } else { "" }
                );
                loaded.push((name.clone(), watch_only));
                registry.insert(handle);
                actor_tasks.push((name.clone(), task));
            }
            // A failed account-to-keys binding check is evidence the wallet database (or
            // keys.toml) was replaced, so it is fatal for the whole daemon, like the
            // single-spending-wallet invariant: zecd won't quietly keep serving the other
            // wallets while one of them shows signs of tampering. Any other per-wallet
            // startup failure (unreadable database, missing files) skips just that wallet.
            Err(e) if e.downcast_ref::<binding::BindingMismatch>().is_some() => {
                shutdown_tx.send_replace(true);
                return Err(e);
            }
            Err(e) => error!("failed to start wallet '{}': {e}", name),
        }
    }

    if registry.is_empty() {
        anyhow::bail!(
            "no usable wallets; run `{prog} init` (datadir: {})",
            config.datadir.display()
        );
    }

    // Enforce the single-spending-wallet invariant before serving any RPC. A second spending
    // wallet is a misconfiguration the operator must resolve (zecd won't silently pick which
    // one is "the" spender), so this is fatal - the actors spawned above are torn down by the
    // shutdown signal sent on the early return.
    if let Err(e) = ensure_single_spending_wallet(&loaded) {
        shutdown_tx.send_replace(true);
        return Err(e);
    }

    let state = AppState {
        config: config.clone(),
        auth,
        registry: Arc::new(registry),
        started_at: Instant::now(),
        shutdown_tx: shutdown_tx.clone(),
        shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        work_queue: Arc::new(tokio::sync::Semaphore::new(config.rpc.work_queue)),
        active: crate::state::ActiveCommands::default(),
        operations: Arc::new(crate::operations::OperationRegistry::new()),
    };

    // Translate a termination signal into a graceful shutdown (flag first, so in-flight new
    // requests 503). Both Ctrl-C (SIGINT) and SIGTERM are handled: init systems (systemd,
    // Docker, k8s) stop the daemon with SIGTERM, and the README documents SIGINT/SIGTERM as
    // equivalent stop signals.
    let signal_state = state.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        signal_state.trigger_shutdown();
    });

    // Liveness/readiness probes on a separate port (best-effort; non-fatal if it can't bind).
    tokio::spawn(health::run(state.clone()));

    let result = server::run(state).await;

    // Stop the wallet actors and wait for them so the WalletDb is dropped cleanly rather than
    // the task being killed mid-write at runtime teardown. The send also covers the case where
    // `server::run` returned on its own (e.g. a bind error) without a shutdown trigger.
    shutdown_tx.send_replace(true);
    let actor_stop_deadline = Duration::from_secs(30);
    for (name, task) in actor_tasks {
        match tokio::time::timeout(actor_stop_deadline, task).await {
            Ok(_) => info!("wallet '{name}' stopped"),
            Err(_) => {
                warn!("wallet '{name}' did not stop within {actor_stop_deadline:?}; exiting anyway")
            }
        }
    }

    // bitcoind removes its generated .cookie on clean shutdown so a stale credential can't
    // linger; do the same. Only applies when cookie auth was in use (no user/password set).
    if config.rpc.user.is_none() || config.rpc.password.is_none() {
        if let Some(cookie) = &config.rpc.cookiefile {
            match std::fs::remove_file(cookie) {
                Ok(()) => info!("removed cookie file {}", cookie.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("could not remove cookie file {}: {e}", cookie.display()),
            }
        }
    }
    result
}

/// Await the first termination signal and return so the caller can trigger a graceful shutdown.
///
/// Both SIGINT (Ctrl-C) and SIGTERM are treated identically - the README advertises them as
/// interchangeable stop signals, and process managers stop the daemon with SIGTERM. On non-Unix
/// platforms only Ctrl-C is available. If the SIGTERM handler can't be installed we fall back to
/// Ctrl-C alone rather than aborting startup.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(term) => term,
            Err(e) => {
                warn!("could not install SIGTERM handler: {e}; only Ctrl-C will stop the daemon");
                let _ = tokio::signal::ctrl_c().await;
                info!("received Ctrl-C, shutting down");
                return;
            }
        };
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                if r.is_ok() {
                    info!("received Ctrl-C, shutting down");
                }
            }
            _ = term.recv() => info!("received SIGTERM, shutting down"),
        }
    }
    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_ok() {
            info!("received Ctrl-C, shutting down");
        }
    }
}

/// True when the RPC password was supplied as a `--rpcpassword` command-line argument (handling
/// both `--rpcpassword VALUE` and `--rpcpassword=VALUE` forms), as opposed to the
/// `ZECD_RPC_PASSWORD` environment variable or `[rpc] password_file`. clap merges the flag and its
/// env fallback into one field, so the raw argv is the only way to tell them apart. Argv is the
/// more exposed of the two: `/proc/<pid>/cmdline` is world-readable and shows up in `ps`, while
/// `/proc/<pid>/environ` is readable only by the process owner - hence the env-var recommendation.
fn rpcpassword_on_cli<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    args.into_iter().any(|a| {
        let a = a.as_ref().to_string_lossy();
        a == "--rpcpassword" || a.starts_with("--rpcpassword=")
    })
}

/// Log the configured RPC authentication method(s) at startup, mirroring the credential union
/// `Authenticator::from_config` accepts: salted `rpcauth` entries, a bare `rpcuser`/`rpcpassword`
/// pair, and/or a generated cookie file (used whenever no bare pair is set). A bare password on a
/// non-loopback bind is called out at WARN: zecd serves plaintext HTTP, so the credential would
/// cross the network in the clear. A password passed via `--rpcpassword` on the command line
/// (`password_on_cli`) is called out separately: it leaks to any local user through
/// `/proc/<pid>/cmdline` and `ps`, independent of the bind address.
fn log_auth_mode(rpc: &config::RpcConfig, password_on_cli: bool) {
    if !rpc.auth.is_empty() {
        info!("RPC auth: {} salted rpcauth credential(s)", rpc.auth.len());
    }
    if rpc.user.is_some() && rpc.password.is_some() {
        info!("RPC auth: rpcuser/rpcpassword (bare password)");
        if !rpc.bind.is_loopback() {
            warn!(
                "RPC is bound to non-loopback {} with a bare rpcpassword; credentials cross the \
                 network in plaintext (zecd serves plaintext HTTP). Bind to localhost, or place \
                 zecd behind a TLS-terminating proxy.",
                rpc.bind
            );
        }
    } else if let Some(cookie) = &rpc.cookiefile {
        info!("RPC auth: cookie file {}", cookie.display());
    }
    if password_on_cli {
        warn!(
            "RPC password was passed via --rpcpassword on the command line; it is exposed to \
             any local user through `ps` and /proc/<pid>/cmdline. Prefer the ZECD_RPC_PASSWORD \
             environment variable or `[rpc] password_file` (a mounted Secret) instead."
        );
    }
}

/// Enforce zecd's single-spending-wallet rule: at most one loaded wallet may hold spending
/// keys, while any number of watch-only (UFVK) wallets may be loaded alongside it. `loaded`
/// pairs each successfully-opened wallet name with its watch-only flag (`true` = watch-only),
/// in a stable order so the error names the offending wallets deterministically. Returns an
/// error naming the two spending wallets when more than one is present.
fn ensure_single_spending_wallet(loaded: &[(String, bool)]) -> anyhow::Result<()> {
    let mut spenders = loaded
        .iter()
        .filter(|(_, watch_only)| !watch_only)
        .map(|(name, _)| name.as_str());
    if let (Some(first), Some(second)) = (spenders.next(), spenders.next()) {
        anyhow::bail!(
            "multiple spending wallets configured ('{first}' and '{second}'); zecd allows at \
             most one wallet with spending keys (any number of watch-only UFVK wallets may be \
             loaded alongside it). Convert one to watch-only (`zecd export-ufvk` + \
             `zecd init --ufvk`) or remove it from the configuration."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_single_spending_wallet, rpcpassword_on_cli};

    fn wallets(entries: &[(&str, bool)]) -> Vec<(String, bool)> {
        entries
            .iter()
            .map(|(name, watch_only)| (name.to_string(), *watch_only))
            .collect()
    }

    #[test]
    fn no_wallets_is_allowed() {
        // The empty case is guarded separately (registry.is_empty bail); the invariant check
        // itself must not error on it.
        assert!(ensure_single_spending_wallet(&[]).is_ok());
    }

    #[test]
    fn single_spending_wallet_is_allowed() {
        assert!(ensure_single_spending_wallet(&wallets(&[("default", false)])).is_ok());
    }

    #[test]
    fn only_watch_only_wallets_is_allowed() {
        // No spending wallet at all is fine (every wallet is a watch-only UFVK import).
        assert!(ensure_single_spending_wallet(&wallets(&[
            ("view-a", true),
            ("view-b", true),
            ("view-c", true),
        ]))
        .is_ok());
    }

    #[test]
    fn one_spending_plus_many_watch_only_is_allowed() {
        assert!(ensure_single_spending_wallet(&wallets(&[
            ("default", false),
            ("view-a", true),
            ("view-b", true),
        ]))
        .is_ok());
    }

    #[test]
    fn two_spending_wallets_are_rejected() {
        let err = ensure_single_spending_wallet(&wallets(&[("default", false), ("second", false)]))
            .expect_err("two spending wallets must be rejected");
        let msg = err.to_string();
        // The error names both offenders so the operator knows which to convert/remove.
        assert!(msg.contains("'default'"), "{msg}");
        assert!(msg.contains("'second'"), "{msg}");
        assert!(msg.contains("at most one"), "{msg}");
    }

    #[test]
    fn two_spending_wallets_mixed_with_watch_only_are_rejected() {
        // Watch-only wallets interleaved with the spenders don't mask the violation; the first
        // two spenders in order are named.
        let err = ensure_single_spending_wallet(&wallets(&[
            ("view-a", true),
            ("spend-a", false),
            ("view-b", true),
            ("spend-b", false),
        ]))
        .expect_err("two spending wallets must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("'spend-a'"), "{msg}");
        assert!(msg.contains("'spend-b'"), "{msg}");
    }

    #[test]
    fn rpcpassword_on_cli_detects_both_flag_forms() {
        // Separate-value form: `--rpcpassword hunter2`.
        assert!(rpcpassword_on_cli([
            "zecd",
            "--rpcport",
            "8232",
            "--rpcpassword",
            "hunter2"
        ]));
        // Joined form: `--rpcpassword=hunter2`.
        assert!(rpcpassword_on_cli(["zecd", "--rpcpassword=hunter2"]));
    }

    #[test]
    fn rpcpassword_on_cli_ignores_env_and_other_flags() {
        // No `--rpcpassword` on argv (the password came from ZECD_RPC_PASSWORD or a file).
        assert!(!rpcpassword_on_cli(["zecd", "--rpcuser", "u", "--testnet"]));
        // A different flag that merely shares a prefix must not match.
        assert!(!rpcpassword_on_cli(["zecd", "--rpcpassword-file", "/x"]));
        assert!(!rpcpassword_on_cli(["zecd"]));
    }
}
