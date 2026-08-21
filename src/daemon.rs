//! Daemon wiring for the `zecd` binary: tracing init, the embeddable node
//! ([`crate::node`]) composed with the health and RPC servers, and graceful shutdown.

#[cfg(feature = "server")]
use tracing::{info, warn};

#[cfg(any(feature = "cli", feature = "server"))]
use crate::config;
#[cfg(feature = "server")]
use crate::config::AppConfig;
#[cfg(feature = "server")]
use crate::health;
#[cfg(feature = "server")]
use crate::server;

/// Initialize tracing. The filter defaults to `[log] level` and is overridden by `RUST_LOG`;
/// `[log] format = "json"` emits structured logs for cloud-native log aggregation.
///
/// `cli`-gated (it is the binary's tracing init, on tracing-subscriber): a library consumer
/// owns its process's tracing subscriber and must not have one installed under it.
#[cfg(feature = "cli")]
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

#[cfg(feature = "server")]
pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    // One identifying line before anything can fail or connect - ahead of even the datadir
    // lock, so a refusal to start is still attributable to a build and a datadir. Both
    // documented stuck-sync incidents came down to "which zecd build, on which network,
    // against which upstream", and the connect path logs the *upstream's* version while
    // nothing logged zecd's own. This is the binary's banner: an embedded node
    // (`crate::node`) is started by a host that owns its own startup logging.
    info!(
        version = env!("CARGO_PKG_VERSION"),
        network = config.network.name(),
        datadir = %config.datadir.display(),
        backend = %config.backend.server,
        "starting zecd"
    );
    // Fail-fast phase first (datadir lock, placeholder-password refusal, panic hook), then the
    // HTTP-only startup work, then the wallet spawns - the order the daemon has always had. The
    // auth construction sits between the two node phases on purpose: a bad rpcauth entry must
    // fail before any wallet actor is spawned, and its cookie-file side effect belongs to the
    // binary, never to the embeddable node (see `crate::node`).
    let prepared = crate::node::NodeBuilder::new(config).prepare()?;
    let auth = server::auth::Authenticator::from_config(&prepared.config().rpc)?;
    log_auth_mode(
        &prepared.config().rpc,
        rpcpassword_on_cli(std::env::args_os()),
    );
    let node = prepared.start().await?;

    let state = node.app_state().clone();

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

    let result = server::run(server::HttpState { app: state, auth }).await;

    // Stop the wallet actors and wait for them so the WalletDb is dropped cleanly rather than
    // the task being killed mid-write at runtime teardown. `Node::shutdown` re-sends the
    // shutdown signal, which also covers the case where `server::run` returned on its own
    // (e.g. a bind error) without a shutdown trigger.
    let config = node.app_state().config.clone();
    node.shutdown().await;

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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
fn log_auth_mode(rpc: &config::RpcConfig, password_on_cli: bool) {
    if !rpc.auth.is_empty() {
        info!(target: "zecd::audit", "RPC auth: {} salted rpcauth credential(s)", rpc.auth.len());
    }
    if rpc.user.is_some() && rpc.password.is_some() {
        info!(target: "zecd::audit", "RPC auth: rpcuser/rpcpassword (bare password)");
        if !rpc.bind.is_loopback() {
            warn!(
                target: "zecd::audit",
                "RPC is bound to non-loopback {} with a bare rpcpassword; credentials cross the \
                 network in plaintext (zecd serves plaintext HTTP). Bind to localhost, or place \
                 zecd behind a TLS-terminating proxy.",
                rpc.bind
            );
        }
    } else if let Some(cookie) = &rpc.cookiefile {
        info!(target: "zecd::audit", "RPC auth: cookie file {}", cookie.display());
    }
    if password_on_cli {
        warn!(
            target: "zecd::audit",
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
pub(crate) fn ensure_single_spending_wallet(loaded: &[(String, bool)]) -> anyhow::Result<()> {
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
    use super::ensure_single_spending_wallet;
    #[cfg(feature = "server")]
    use super::rpcpassword_on_cli;
    /// Fixture helper: name/watch-only pairs in the shape the guard consumes.
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

    #[cfg(feature = "server")]
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

    #[cfg(feature = "server")]
    #[test]
    fn rpcpassword_on_cli_ignores_env_and_other_flags() {
        // No `--rpcpassword` on argv (the password came from ZECD_RPC_PASSWORD or a file).
        assert!(!rpcpassword_on_cli(["zecd", "--rpcuser", "u", "--testnet"]));
        // A different flag that merely shares a prefix must not match.
        assert!(!rpcpassword_on_cli(["zecd", "--rpcpassword-file", "/x"]));
        assert!(!rpcpassword_on_cli(["zecd"]));
    }
}
