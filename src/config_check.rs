//! `zecd config check` - validate a configuration file against *this* zecd build, and print the
//! settings it resolves to, without starting the daemon.
//!
//! zecd rejects unknown config keys, which is what keeps a typo'd knob from being silently
//! ignored - but it means a config written for one build can be refused by another. That cuts
//! both ways on an upgrade (a key this build has not learned yet) and on a rollback (a key it
//! no longer has), and the only way to find out used to be to start the daemon on the target
//! host. This command answers the same question offline: run the binary you are about to deploy
//! against the config you are about to deploy, and it either resolves or it doesn't.
//!
//! Two properties are load-bearing:
//!
//! * **It reaches the daemon's verdict, not a second opinion.** Every check here is either
//!   `AppConfig::resolve` itself or a helper the daemon calls at startup/connect
//!   ([`config::reject_placeholder_password`](crate::config::reject_placeholder_password),
//!   [`Server::preflight`](crate::backend::Server::preflight),
//!   [`auth::check_config`](crate::server::auth::check_config)). Nothing re-implements a rule.
//! * **It changes nothing.** No datadir lock (so it runs alongside a live daemon), no wallet
//!   database is opened, and in particular no cookie file is minted - `Authenticator::from_config`
//!   writes one as a side effect, which would invalidate the credential a running daemon handed
//!   out, so the check uses the side-effect-free `auth::check_config` instead.
//!
//! What it deliberately cannot do is anything requiring the network or the wallet: whether zebra
//! is actually reachable, whether the seed matches the account, whether the chain is the one the
//! wallet expects. Those need a running daemon, and saying so is more useful than guessing.
//!
//! Output follows the `nginx -t`/`-T` convention: **stdout is the effective configuration,
//! stderr is the verdict** (see [`run`]).

use std::io::Write;

use crate::config::{AppConfig, Cli, ConfigCheckArgs};

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The daemon would refuse to start, or would start but never reach a usable state (a
    /// connect that is refused before any packet is sent). Fails the check.
    Error,
    /// Legal, resolvable configuration that is risky, environment-dependent, or probably not
    /// what was meant. Reported, but only fails the check under `--strict`.
    Warning,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warning => "warning",
        }
    }
}

/// One thing worth telling the operator about a resolved configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub message: String,
}

impl Finding {
    fn error(message: impl Into<String>) -> Finding {
        Finding {
            level: Level::Error,
            message: message.into(),
        }
    }

    fn warning(message: impl Into<String>) -> Finding {
        Finding {
            level: Level::Warning,
            message: message.into(),
        }
    }
}

/// Everything that can be checked about an already-resolved config without a network or a
/// wallet database. Filesystem *existence* probes are included (they are what turns "this TOML
/// parses" into "this deployment would come up"), which is why several findings are warnings:
/// a config checked on a workstation legitimately points at paths that only exist on the host.
pub fn inspect(config: &AppConfig) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Startup policy, shared verbatim with `daemon::run`.
    if let Err(e) = crate::config::reject_placeholder_password(config) {
        findings.push(Finding::error(format!("{e:#}")));
    }

    check_backend(config, &mut findings);
    check_rpc(config, &mut findings);
    check_paths(config, &mut findings);

    findings
}

/// The upstream endpoint: the token must resolve, and the connect-time checks that need no
/// network must pass. A refusal there is an error rather than a warning because the daemon
/// would start and then fail every connect attempt forever - a wallet that can never sync.
fn check_backend(config: &AppConfig, findings: &mut Vec<Finding>) {
    let server = match crate::backend::resolve_configured(config) {
        Ok(server) => server,
        Err(e) => {
            findings.push(Finding::error(format!("[backend] server: {e:#}")));
            return;
        }
    };
    if let Err(e) = server.preflight() {
        findings.push(Finding::error(format!("{e:#}")));
    }

    let lightwalletd = server.kind() == crate::backend::ServerKind::Lightwalletd;
    if config.backend.assume_transparent_in_compact_blocks && !lightwalletd {
        findings.push(Finding::warning(
            "[backend] assume_transparent_in_compact_blocks is set but the upstream is not a \
             lightwalletd; it will be ignored (a zebra backend always covers transparent data)",
        ));
    }
    if config.backend.tls_insecure_skip_verify {
        findings.push(Finding::warning(
            "[backend] tls_insecure_skip_verify = true accepts any lightwalletd certificate: \
             the connection is encrypted but unauthenticated, so an on-path attacker can \
             impersonate the server. Prefer tls_pinned_sha256 for a self-signed certificate",
        ));
    }

    for (name, wallet) in &config.wallets {
        if !wallet.transparent_enabled {
            continue;
        }
        // The actor refuses to run a transparent-enabled wallet against a lightwalletd that
        // does not advertise transparent data in compact blocks - and no released lightwalletd
        // populates the advertisement, so in practice the assertion knob is required. Only a
        // warning: whether a given server advertises it is a fact about the server, not the
        // config, and this check never dials.
        if lightwalletd && !config.backend.assume_transparent_in_compact_blocks {
            findings.push(Finding::warning(format!(
                "wallet '{name}' has [pools] transparent = true against a lightwalletd upstream: \
                 the wallet refuses to run unless the server advertises that it serves \
                 transparent data in compact blocks, and no released lightwalletd populates that \
                 advertisement yet. Set [backend] assume_transparent_in_compact_blocks = true to \
                 assert it, or point [backend] server at your own zebra"
            )));
        }
        if lightwalletd
            && (wallet.transparent_initial_scan >= LIGHT_TRANSPARENT_ADDR_WARN
                || wallet.transparent_gap_limit >= LIGHT_TRANSPARENT_ADDR_WARN)
        {
            findings.push(Finding::warning(format!(
                "wallet '{name}': transparent_initial_scan = {} / transparent_gap_limit = {} on a \
                 lightwalletd backend - spend detection queries each funded address separately, \
                 one remote round trip apiece. Running your own zebra (server = \"zebra\") is \
                 recommended at this scale",
                wallet.transparent_initial_scan, wallet.transparent_gap_limit,
            )));
        }
    }
}

/// Mirrors `daemon.rs`'s per-wallet lightwalletd scale warning.
const LIGHT_TRANSPARENT_ADDR_WARN: u32 = 1_000;

/// The RPC surface: the credentials must be usable, and a bare password must not be about to
/// cross a network in the clear (zecd serves plaintext HTTP).
fn check_rpc(config: &AppConfig, findings: &mut Vec<Finding>) {
    if let Err(e) = crate::server::auth::check_config(&config.rpc) {
        findings.push(Finding::error(format!("{e:#}")));
    }
    if config.rpc.user.is_some() && config.rpc.password.is_some() && !config.rpc.bind.is_loopback()
    {
        findings.push(Finding::warning(format!(
            "[rpc] bind = {} is not loopback and a bare rpcuser/rpcpassword is set; credentials \
             would cross the network in plaintext (zecd serves plaintext HTTP). Bind to \
             localhost, or place zecd behind a TLS-terminating proxy",
            config.rpc.bind
        )));
    }
}

/// Paths and per-wallet settings. Everything here is environment-dependent, so it warns rather
/// than errors: the same config is legitimately checked on a machine that is not the target.
fn check_paths(config: &AppConfig, findings: &mut Vec<Finding>) {
    // A missing datadir is deliberately *not* reported: the daemon creates it (and the cookie
    // file's parent, and each wallet directory) on startup, so warning about it would be a
    // claim of failure that never happens. What a missing datadir really implies - no wallet
    // there yet - is covered precisely by the per-wallet check below.
    if let Some(cookie) = &config.zebra.rpc_cookie {
        if !cookie.exists() {
            findings.push(Finding::warning(format!(
                "[zebra] rpc_cookie {} does not exist; it is read on every connect, so the \
                 wallet cannot reach zebrad until zebrad has written it",
                cookie.display()
            )));
        }
    }

    let mut initialized = 0usize;
    for (name, wallet) in &config.wallets {
        let keys_path = wallet.keys_path();
        if crate::wallet::store::WalletStore::exists(&keys_path) {
            initialized += 1;
        } else {
            findings.push(Finding::warning(format!(
                "wallet '{name}' is not initialized ({} is missing); the daemon skips it (run \
                 `zecd init --wallet {name}`)",
                keys_path.display()
            )));
        }

        // Recording a transparent receive re-derives the whole gap window, so a wide window is
        // a per-receive cost, not just a restore-scan depth. The actor logs this at spawn; here
        // it is worth catching before the config reaches a host at all.
        if wallet.transparent_enabled {
            if wallet.transparent_gap_limit > crate::config::TRANSPARENT_GAP_LIMIT_SEVERE {
                findings.push(Finding::warning(format!(
                    "wallet '{name}': transparent_gap_limit = {} will effectively STALL restores \
                     and slow every incoming transparent payment (recording one transparent \
                     receive re-derives the entire gap window, roughly {}s of address derivation \
                     per received UTXO). Use a small gap limit plus [pools] \
                     transparent_initial_scan for deep restore coverage instead",
                    wallet.transparent_gap_limit,
                    wallet.transparent_gap_limit / 1200
                )));
            } else if wallet.transparent_gap_limit > crate::config::TRANSPARENT_GAP_LIMIT_COSTLY {
                findings.push(Finding::warning(format!(
                    "wallet '{name}': transparent_gap_limit = {} is unusually large; every \
                     transparent receive re-derives the entire gap window. Prefer a small gap \
                     limit plus [pools] transparent_initial_scan",
                    wallet.transparent_gap_limit
                )));
            }
        }
    }
    if initialized == 0 && !config.wallets.is_empty() {
        findings.push(Finding::warning(format!(
            "no configured wallet is initialized; the daemon would exit with \"no usable \
             wallets\" (datadir: {})",
            config.datadir.display()
        )));
    }
}

/// The effective settings, rendered by [`crate::config_show`] - the same text `zecd config
/// show` prints. One renderer rather than two: a check that described the configuration in its
/// own vocabulary would invent labels that map to no config key, and would drift from `show` the
/// first time a knob was added. What `check` adds is the verdict, on stderr.
fn summary(config: &AppConfig) -> String {
    crate::config_show::render(config)
}

/// `zecd config check`.
///
/// **stdout carries the effective configuration; stderr carries the verdict.** That is `nginx`'s
/// split (`nginx -t`'s "syntax is ok" goes to stderr precisely so `nginx -T` can put pure config
/// on stdout), and it is what makes the two jobs this command does separable:
/// `zecd config check --conf f > effective.txt` captures exactly the settings, so diffing two
/// binaries' output is diffing configuration and nothing else, while the findings and the pass/
/// fail line stay where diagnostics belong. With `-q` stdout is empty, so a CI gate is silent on
/// success and still loud on stderr when it isn't.
pub fn run(cli: &Cli, args: &ConfigCheckArgs) -> anyhow::Result<()> {
    let conf_path = AppConfig::conf_path(cli);
    emit_err(&format!(
        "zecd {}\nconfig file: {}\n",
        env!("CARGO_PKG_VERSION"),
        conf_path.display()
    ));

    // Unlike the daemon, a missing file is a failure rather than "use the built-in defaults":
    // checking a config that isn't there is a typo'd path or a bad assumption about where the
    // file lives, and silently validating the defaults instead would confirm neither.
    if !conf_path.exists() {
        anyhow::bail!(
            "no config file at {} (the daemon would fall back to built-in defaults; \
             pass --conf FILE or --datadir DIR to point at the file to check)",
            conf_path.display()
        );
    }

    let config = match AppConfig::resolve(cli) {
        Ok(config) => config,
        Err(e) => {
            // Nothing reaches stdout: a config that doesn't resolve has no effective settings
            // to report, so the capture is empty rather than half-written.
            emit_err(&format!("\n{}: {e:#}\n", Level::Error.label()));
            anyhow::bail!(
                "{} is not valid for zecd {}",
                conf_path.display(),
                env!("CARGO_PKG_VERSION")
            );
        }
    };

    let findings = inspect(&config);
    if !args.quiet {
        emit(&summary(&config));
    }
    let mut report = String::new();
    if !findings.is_empty() {
        report.push('\n');
        for f in &findings {
            report.push_str(&format!("{}: {}\n", f.level.label(), f.message));
        }
    }

    let errors = findings.iter().filter(|f| f.level == Level::Error).count();
    let warnings = findings.len() - errors;
    if errors == 0 && !(args.strict && warnings > 0) && !args.quiet {
        report.push_str(&format!(
            "\nOK: {} is valid for zecd {}{}\n",
            conf_path.display(),
            env!("CARGO_PKG_VERSION"),
            plural_suffix(warnings, " ({} warning{})"),
        ));
    }
    emit_err(&report);

    if errors > 0 {
        anyhow::bail!(
            "{errors} error{} in {}",
            if errors == 1 { "" } else { "s" },
            conf_path.display()
        );
    }
    if args.strict && warnings > 0 {
        anyhow::bail!(
            "{warnings} warning{} in {} (--strict)",
            if warnings == 1 { "" } else { "s" },
            conf_path.display()
        );
    }
    Ok(())
}

/// `" ({} warning{})"` filled in for `n`, or empty when there is nothing to report.
fn plural_suffix(n: usize, template: &str) -> String {
    if n == 0 {
        return String::new();
    }
    template
        .replacen("{}", &n.to_string(), 1)
        .replacen("{}", if n == 1 { "" } else { "s" }, 1)
}

/// Write the effective configuration to stdout, treating a closed pipe as a clean exit
/// (`zecd config check | head` would otherwise *panic* through `print!`, since the macros panic
/// on EPIPE).
fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
}

/// Write a diagnostic - the header, the findings, the verdict - to stderr. Flushed as it goes, so
/// it interleaves with [`emit`] in the order written when both are a terminal.
fn emit_err(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes()).and_then(|()| err.flush());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::path::Path;

    /// Parse a CLI the way `main` does, so the tests exercise the real argument surface
    /// (including that the global flags are accepted *after* the subcommand).
    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("zecd").chain(args.iter().copied()))
            .expect("parsing the test command line")
    }

    fn write_config(dir: &Path, text: &str) -> std::path::PathBuf {
        let path = dir.join("zecd.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn resolve(text: &str, dir: &Path) -> AppConfig {
        let path = write_config(dir, text);
        AppConfig::resolve(&cli(&["--conf", path.to_str().unwrap()])).expect("valid config")
    }

    fn errors(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .filter(|f| f.level == Level::Error)
            .map(|f| f.message.as_str())
            .collect()
    }

    fn warnings(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .filter(|f| f.level == Level::Warning)
            .map(|f| f.message.as_str())
            .collect()
    }

    /// The global flags must be accepted on either side of the subcommand - `zecd config check
    /// --conf FILE` is the spelling operators reach for, and it is the one that would silently
    /// not exist if `conf` were positional to the top-level command.
    #[test]
    fn conf_is_accepted_before_and_after_the_subcommand() {
        for args in [
            vec!["--conf", "/etc/zecd/zecd.toml", "config", "check"],
            vec!["config", "check", "--conf", "/etc/zecd/zecd.toml"],
        ] {
            let parsed = cli(&args);
            assert_eq!(
                AppConfig::conf_path(&parsed),
                Path::new("/etc/zecd/zecd.toml"),
                "{args:?}"
            );
        }
    }

    /// A config with no upstream/wallet problems produces no *errors*; the wallet-not-initialized
    /// warning is expected (the tempdir holds only the TOML).
    #[test]
    fn a_plain_testnet_config_has_no_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config = resolve(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
                dir.path()
            ),
            dir.path(),
        );
        let findings = inspect(&config);
        assert!(errors(&findings).is_empty(), "{findings:?}");
        assert!(
            warnings(&findings)
                .iter()
                .any(|w| w.contains("not initialized")),
            "{findings:?}"
        );
    }

    /// The mainnet placeholder refusal is the daemon's, reached through the shared helper.
    #[test]
    fn mainnet_placeholder_password_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = resolve(
            &format!(
                "network = \"main\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"change-me\"\n",
                dir.path()
            ),
            dir.path(),
        );
        assert!(
            errors(&inspect(&config))
                .iter()
                .any(|e| e.contains("CHANGE-ME")),
            "{:?}",
            inspect(&config)
        );
    }

    /// A credentialed `zebra://` endpoint on a public host is refused by the cleartext gate at
    /// connect. The daemon would start and then never sync, so the check reports it as an error
    /// - the case this command exists to catch before a deployment, not after.
    #[test]
    fn credentialed_zebra_over_the_public_internet_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = resolve(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n[backend]\nserver = \"zebra://203.0.113.7:8232\"\n\
                 [zebra]\nrpc_user = \"u\"\nrpc_password = \"p\"\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
                dir.path()
            ),
            dir.path(),
        );
        assert!(
            errors(&inspect(&config))
                .iter()
                .any(|e| e.contains("cleartext")),
            "{:?}",
            inspect(&config)
        );

        // ...and the documented opt-out clears it.
        let config = resolve(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n[backend]\nserver = \"zebra://203.0.113.7:8232\"\n\
                 allow_remote_cleartext = true\n\
                 [zebra]\nrpc_user = \"u\"\nrpc_password = \"p\"\n[rpc]\nuser = \"u\"\npassword = \"p\"\n",
                dir.path()
            ),
            dir.path(),
        );
        assert!(
            errors(&inspect(&config)).is_empty(),
            "{:?}",
            inspect(&config)
        );
    }

    /// A transparent-enabled wallet on a lightwalletd upstream refuses to run unless the
    /// capability is asserted - the single most likely way a light-mode transparent deployment
    /// fails, and invisible in the config file itself.
    #[test]
    fn transparent_on_lightwalletd_warns_without_the_capability_assertion() {
        let dir = tempfile::tempdir().unwrap();
        let base = format!(
            "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n\
             [pools]\ntransparent = true\n[backend]\nserver = \"zecrocks\"\n",
            dir.path()
        );
        let config = resolve(&base, dir.path());
        assert!(
            warnings(&inspect(&config))
                .iter()
                .any(|w| w.contains("transparent data in compact blocks")),
            "{:?}",
            inspect(&config)
        );

        let config = resolve(
            &format!("{base}assume_transparent_in_compact_blocks = true\n"),
            dir.path(),
        );
        assert!(
            !warnings(&inspect(&config))
                .iter()
                .any(|w| w.contains("transparent data in compact blocks")),
            "{:?}",
            inspect(&config)
        );
    }

    /// The gap-limit width that stalled a real restore is warned about here too, so it can be
    /// caught before the config ships rather than in the actor's startup log afterwards.
    #[test]
    fn a_pathological_transparent_gap_limit_warns() {
        let dir = tempfile::tempdir().unwrap();
        let config = resolve(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n[rpc]\nuser = \"u\"\npassword = \"p\"\n\
                 [pools]\ntransparent = true\ntransparent_gap_limit = 71000\n",
                dir.path()
            ),
            dir.path(),
        );
        assert!(
            warnings(&inspect(&config))
                .iter()
                .any(|w| w.contains("STALL")),
            "{:?}",
            inspect(&config)
        );
    }

    /// A bare password on a non-loopback bind crosses the network in the clear (zecd is
    /// plaintext HTTP) - the same call-out the daemon logs at startup.
    #[test]
    fn a_bare_password_on_a_public_bind_warns() {
        let dir = tempfile::tempdir().unwrap();
        let config = resolve(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n[rpc]\nbind = \"0.0.0.0\"\nuser = \"u\"\npassword = \"p\"\n",
                dir.path()
            ),
            dir.path(),
        );
        assert!(
            warnings(&inspect(&config))
                .iter()
                .any(|w| w.contains("plaintext")),
            "{:?}",
            inspect(&config)
        );
    }

    /// What `check` prints as the effective settings is exactly what `config show` prints -
    /// one renderer, so the two commands can never describe the same config differently.
    #[test]
    fn the_summary_is_the_config_show_rendering() {
        let dir = tempfile::tempdir().unwrap();
        let config = resolve(
            &format!("network = \"test\"\ndatadir = {:?}\n", dir.path()),
            dir.path(),
        );
        assert_eq!(summary(&config), crate::config_show::render(&config));
        // ...and it carries what the file never said, which is the upgrade/rollback half of the
        // command (`config_show`'s own tests pin the format).
        assert!(
            summary(&config).contains("privacy_policy = \"AllowRevealedRecipients\""),
            "{}",
            summary(&config)
        );
    }

    #[test]
    fn plural_suffix_reads_correctly() {
        assert_eq!(plural_suffix(0, " ({} warning{})"), "");
        assert_eq!(plural_suffix(1, " ({} warning{})"), " (1 warning)");
        assert_eq!(plural_suffix(3, " ({} warning{})"), " (3 warnings)");
    }
}
