//! `zecd config show` - print the effective configuration in the config file's own syntax.
//!
//! `sshd -T` to `config check`'s `sshd -t`. A zecd config file is only half the configuration:
//! every key it leaves unset takes this build's default, and those move between versions. This
//! renders what the binary actually resolved - file, CLI overrides, environment and defaults all
//! collapsed - as TOML, so it can be diffed across two binaries, captured before an upgrade, or
//! read to answer "what is this daemon actually doing" without cross-referencing the docs.
//!
//! TOML rather than a prose summary for two reasons. It names **real config keys**, so a line
//! that surprises you is a line you can go and change (a hand-formatted summary invents labels
//! that map to nothing). And it re-parses: [`tests::render_is_idempotent_through_a_resolve`]
//! feeds the output back through `AppConfig::resolve` and requires the second render to be
//! identical, which pins every emitted key as one this build's parser accepts - `deny_unknown_fields`
//! turns any drift between the renderer and the schema into a failing test rather than output
//! that looks authoritative and isn't.
//!
//! **Secrets are redacted, so this is an inspection view rather than a drop-in config file.**
//! The RPC password, the `rpcauth` credential hashes and the `[zebra]` credentials are emitted
//! as commented-out lines naming the key but not the value. Commented rather than
//! `password = "<redacted>"` deliberately: a redacted placeholder that *parses* would silently
//! become a real (wrong) credential if the file were ever deployed, whereas an absent password
//! falls back to cookie auth, which fails loudly and safely. The cost is that a config carrying
//! secrets does not round-trip byte-for-byte - which is the honest outcome, since the daemon's
//! behaviour genuinely depends on values that must not be printed.

#[cfg(feature = "cli")]
use std::io::Write;
use std::path::Path;

use crate::config::AppConfig;
#[cfg(feature = "cli")]
use crate::config::{Cli, ConfigShowArgs};

/// Preamble on the rendered config, explaining what the reader is looking at. Deliberately free
/// of the version and the source path - those are provenance, and they go to stderr like
/// `config check`'s header, so that two versions' stdout differ only where the configuration
/// differs.
const HEADER: &str = "\
# The EFFECTIVE zecd configuration: the config file, CLI flags and environment resolved
# together, with every unset key filled in by this build's default. Diff two zecd versions'
# output to see which defaults moved.
#
# Secrets (the RPC password, rpcauth hashes, [zebra] credentials) are shown as commented-out
# key names, never values - so this is an inspection view, not a drop-in config file.
";

/// Render `config` as TOML.
pub fn render(config: &AppConfig) -> String {
    let mut s = String::from(HEADER);

    // Top-level scalars first: in TOML every key after a `[table]` header belongs to that table.
    s.push('\n');
    kv(&mut s, "network", str_val(config.network.name()));
    kv(&mut s, "datadir", path_val(&config.datadir));
    kv(&mut s, "default_wallet", str_val(&config.default_wallet));

    table(&mut s, "backend");
    let b = &config.backend;
    // The token is what the operator writes; what it resolves to (host, port, protocol, and for
    // lightwalletd the TLS decision) is the thing they actually want to confirm, and it is not
    // itself a config key - so it rides as a comment, derived from the value beside it.
    match crate::backend::resolve_configured(config) {
        Ok(server) => kv_note(&mut s, "server", str_val(&b.server), &server.describe()),
        Err(e) => kv_note(
            &mut s,
            "server",
            str_val(&b.server),
            &format!("UNRESOLVED: {e}"),
        ),
    }
    kv(&mut s, "connect_timeout_secs", b.connect_timeout_secs);
    kv(&mut s, "reconnect_base_secs", b.reconnect_base_secs);
    kv(&mut s, "reconnect_max_secs", b.reconnect_max_secs);
    kv(&mut s, "rfc1918_is_local", b.rfc1918_is_local);
    kv(&mut s, "allow_remote_cleartext", b.allow_remote_cleartext);
    kv(
        &mut s,
        "tls",
        str_val(match b.tls {
            None => "auto",
            Some(true) => "yes",
            Some(false) => "no",
        }),
    );
    kv(
        &mut s,
        "tls_roots",
        str_val(match b.tls_roots {
            crate::backend::TlsRoots::Native => "native",
            crate::backend::TlsRoots::Webpki => "webpki",
        }),
    );
    kv(
        &mut s,
        "tls_insecure_skip_verify",
        b.tls_insecure_skip_verify,
    );
    if let Some(ca) = &b.tls_ca_file {
        kv(&mut s, "tls_ca_file", path_val(ca));
    }
    if !b.tls_pins.is_empty() {
        let pins: Vec<String> = b.tls_pins.iter().map(|p| p.to_string()).collect();
        kv(&mut s, "tls_pinned_sha256", list_val(&pins));
    }
    kv(
        &mut s,
        "assume_transparent_in_compact_blocks",
        b.assume_transparent_in_compact_blocks,
    );

    table(&mut s, "zebra");
    if let Some(cookie) = &config.zebra.rpc_cookie {
        kv(&mut s, "rpc_cookie", path_val(cookie));
    }
    redacted_pair(
        &mut s,
        &["rpc_user", "rpc_password"],
        config.zebra.rpc_user.is_some() || config.zebra.rpc_password.is_some(),
    );

    table(&mut s, "rpc");
    kv(&mut s, "bind", str_val(&config.rpc.bind.to_string()));
    kv(&mut s, "port", config.rpc.port);
    redacted_pair(
        &mut s,
        &["user", "password"],
        config.rpc.user.is_some() || config.rpc.password.is_some(),
    );
    redacted_pair(&mut s, &["auth"], !config.rpc.auth.is_empty());
    if let Some(cookie) = &config.rpc.cookiefile {
        kv(&mut s, "cookiefile", path_val(cookie));
    }
    kv(&mut s, "work_queue", config.rpc.work_queue);
    kv(
        &mut s,
        "allowed_methods",
        list_val(&config.rpc.allowed_methods),
    );
    kv(
        &mut s,
        "allow_duplicate_shielded_recipients",
        config.rpc.allow_duplicate_shielded_recipients,
    );

    table(&mut s, "keys");
    if let Some(id) = &config.keys.age_identity {
        kv(&mut s, "age_identity", path_val(id));
    }
    kv(&mut s, "auto_unlock", config.keys.auto_unlock);
    kv(
        &mut s,
        "bootstrap_from_keys",
        config.keys.bootstrap_from_keys,
    );

    table(&mut s, "sync");
    kv(&mut s, "interval_secs", config.sync.interval_secs);
    kv(&mut s, "rebroadcast_secs", config.sync.rebroadcast_secs);

    table(&mut s, "spend");
    kv(
        &mut s,
        "trusted_confirmations",
        config.spend.trusted_confirmations,
    );
    kv(
        &mut s,
        "untrusted_confirmations",
        config.spend.untrusted_confirmations,
    );
    // The `Debug` spelling is the config spelling (`SendPrivacy::parse` accepts exactly these),
    // so the rendered value round-trips.
    kv(
        &mut s,
        "privacy_policy",
        str_val(&format!("{:?}", config.spend.privacy)),
    );
    kv(
        &mut s,
        "orchard_action_limit",
        config.spend.orchard_action_limit,
    );
    kv(&mut s, "cache_proving_key", config.spend.cache_proving_key);
    kv(&mut s, "pipeline_proving", config.spend.pipeline_proving);

    table(&mut s, "pools");
    pools_keys(&mut s, &config.pools);

    table(&mut s, "health");
    kv(&mut s, "enabled", config.health.enabled);
    kv(&mut s, "bind", str_val(&config.health.bind.to_string()));
    kv(&mut s, "port", config.health.port);
    kv(
        &mut s,
        "readiness",
        str_val(config.health.readiness.as_str()),
    );
    kv(&mut s, "max_scan_lag", config.health.max_scan_lag);

    table(&mut s, "log");
    kv(&mut s, "level", str_val(&config.log.level));
    kv(&mut s, "format", str_val(&config.log.format));

    // Wallets last: every pool setting is emitted per wallet, resolved, so each entry stands on
    // its own rather than depending on the reader to apply the `[pools]` defaults above.
    for (name, w) in &config.wallets {
        table(&mut s, &format!("wallets.{name}"));
        kv(&mut s, "dir", path_val(&w.dir));
        if let Some(keys_file) = &w.keys_file {
            kv(&mut s, "keys_file", path_val(keys_file));
        }
        // Endpoint overrides are rendered only when this wallet actually sets them: an absent
        // key means "falls back to [backend]", which is what the omission says.
        let bo = &w.backend;
        if let Some(server) = &bo.server {
            match crate::backend::resolve_for_wallet(config, w) {
                Ok(resolved) => kv_note(&mut s, "server", str_val(server), &resolved.describe()),
                Err(e) => kv_note(
                    &mut s,
                    "server",
                    str_val(server),
                    &format!("UNRESOLVED: {e}"),
                ),
            }
        }
        if let Some(tls) = bo.tls {
            kv(
                &mut s,
                "tls",
                str_val(match tls {
                    None => "auto",
                    Some(true) => "yes",
                    Some(false) => "no",
                }),
            );
        }
        if let Some(roots) = bo.tls_roots {
            kv(
                &mut s,
                "tls_roots",
                str_val(match roots {
                    crate::backend::TlsRoots::Native => "native",
                    crate::backend::TlsRoots::Webpki => "webpki",
                }),
            );
        }
        if let Some(skip) = bo.tls_insecure_skip_verify {
            kv(&mut s, "tls_insecure_skip_verify", skip);
        }
        if let Some(ca) = &bo.tls_ca_file {
            kv(&mut s, "tls_ca_file", path_val(ca));
        }
        if let Some(pins) = &bo.tls_pins {
            let pins: Vec<String> = pins.iter().map(|p| p.to_string()).collect();
            kv(&mut s, "tls_pinned_sha256", list_val(&pins));
        }
        if let Some(assume) = bo.assume_transparent_in_compact_blocks {
            kv(&mut s, "assume_transparent_in_compact_blocks", assume);
        }
        kv(&mut s, "pools", list_val(&w.pools.names()));
        kv(
            &mut s,
            "default_receivers",
            list_val(&w.default_receivers.names()),
        );
        kv(&mut s, "transparent", w.transparent_enabled);
        kv(&mut s, "transparent_default", w.transparent_default);
        kv(&mut s, "transparent_gap_limit", w.transparent_gap_limit);
        kv(
            &mut s,
            "transparent_initial_scan",
            w.transparent_initial_scan,
        );
        kv(
            &mut s,
            "transparent_allow_beyond_recovery_window",
            w.transparent_allow_beyond_recovery_window,
        );
        kv(
            &mut s,
            "transparent_gap_warn_threshold",
            w.transparent_gap_warn_threshold,
        );
    }
    s
}

/// The `[pools]` keys, shared by the global table (per-wallet entries spell the same settings
/// under `[wallets.<name>]`, where the key for the pool list is `pools` rather than `enabled`).
fn pools_keys(s: &mut String, pools: &crate::config::PoolsConfig) {
    kv(s, "enabled", list_val(&pools.enabled.names()));
    kv(
        s,
        "default_receivers",
        list_val(&pools.default_receivers.names()),
    );
    kv(s, "transparent", pools.transparent_enabled);
    kv(s, "transparent_default", pools.transparent_default);
    kv(s, "transparent_gap_limit", pools.transparent_gap_limit);
    kv(
        s,
        "transparent_initial_scan",
        pools.transparent_initial_scan,
    );
    kv(
        s,
        "transparent_allow_beyond_recovery_window",
        pools.transparent_allow_beyond_recovery_window,
    );
    kv(
        s,
        "transparent_gap_warn_threshold",
        pools.transparent_gap_warn_threshold,
    );
}

/// `[name]`, preceded by a blank line.
fn table(s: &mut String, name: &str) {
    s.push_str(&format!("\n[{name}]\n"));
}

/// `key = value`, where `value` is already TOML-formatted.
fn kv(s: &mut String, key: &str, value: impl std::fmt::Display) {
    s.push_str(&format!("{key} = {value}\n"));
}

/// `key = value  # note` - for facts that are *derived* from the value (so the comment stays a
/// function of the configuration, and two renders of the same config still match).
fn kv_note(s: &mut String, key: &str, value: impl std::fmt::Display, note: &str) {
    s.push_str(&format!("{key} = {value}  # {note}\n"));
}

/// Name the secret-bearing keys without printing them. Emitted only when something is set, so a
/// config with no credentials renders without the noise.
fn redacted_pair(s: &mut String, keys: &[&str], set: bool) {
    if set {
        s.push_str(&format!("# {} = <redacted>\n", keys.join(", ")));
    }
}

/// A TOML string literal, escaped by the same library that will parse it back.
fn str_val(v: &str) -> String {
    toml::Value::String(v.to_string()).to_string()
}

fn path_val(p: &Path) -> String {
    str_val(&p.display().to_string())
}

fn list_val<S: AsRef<str>>(items: &[S]) -> String {
    toml::Value::Array(
        items
            .iter()
            .map(|i| toml::Value::String(i.as_ref().to_string()))
            .collect(),
    )
    .to_string()
}

/// `zecd config show`.
///
/// Same stream contract as `config check`: the configuration goes to stdout, provenance to
/// stderr, so `zecd config show > effective.toml` captures exactly the config.
///
/// Unlike `config check`, a missing config file is **not** an error here. The two commands
/// answer different questions: `check` validates a file the caller says exists (so a path that
/// isn't there is a typo worth failing on), while `show` reports what this binary would do -
/// which is perfectly well defined with no file at all, and is then the most direct way to see
/// the built-in defaults.
#[cfg(feature = "cli")]
pub fn run(cli: &Cli, _args: &ConfigShowArgs) -> anyhow::Result<()> {
    let conf_path = AppConfig::conf_path(cli);
    let source = if conf_path.exists() {
        format!("config file: {}", conf_path.display())
    } else {
        format!(
            "no config file at {} - showing this build's defaults with any CLI/environment \
             overrides applied",
            conf_path.display()
        )
    };
    emit_err(&format!("zecd {}\n{source}\n", env!("CARGO_PKG_VERSION")));

    let config = AppConfig::resolve(cli)?;
    emit(&render(&config));
    Ok(())
}

/// Write the configuration to stdout, treating a closed pipe as a clean exit (`zecd config show
/// | head` would otherwise *panic* through `print!`, which panics on EPIPE).
#[cfg(feature = "cli")]
fn emit(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|()| out.flush());
}

#[cfg(feature = "cli")]
fn emit_err(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(text.as_bytes()).and_then(|()| err.flush());
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;
    use clap::Parser;

    fn resolve_from(text: &str, dir: &Path) -> AppConfig {
        let path = dir.join("zecd.toml");
        std::fs::write(&path, text).unwrap();
        let cli = Cli::try_parse_from(["zecd", "--conf", path.to_str().unwrap()]).unwrap();
        AppConfig::resolve(&cli).expect("config resolves")
    }

    /// The property that keeps this honest: the rendered config must re-resolve to the same
    /// configuration, and render identically the second time. That pins every emitted key as one
    /// the parser accepts (`deny_unknown_fields` would otherwise let the renderer drift into
    /// producing a config zecd itself would reject) and every emitted *value* as one that parses
    /// back to what it came from.
    ///
    /// Deliberately a secret-free config: redacted keys are emitted as comments, so a config
    /// carrying credentials cannot round-trip by construction (see the module docs).
    #[test]
    fn render_is_idempotent_through_a_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let first = render(&resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [pools]\nenabled = [\"orchard\", \"sapling\"]\ndefault_receivers = [\"orchard\"]\n\
                 transparent = true\ntransparent_gap_limit = 30\n\
                 [spend]\nprivacy_policy = \"FullPrivacy\"\ntrusted_confirmations = 5\n\
                 untrusted_confirmations = 11\n\
                 [health]\nreadiness = \"connected\"\n",
                dir.path()
            ),
            dir.path(),
        ));

        let round_trip = tempfile::tempdir().unwrap();
        let second = render(&resolve_from(&first, round_trip.path()));
        assert_eq!(
            first, second,
            "the effective config must survive being fed back to zecd"
        );

        // ...and it really did carry the settings, rather than round-tripping empty. Note the
        // pool list comes back in `ReceiverSet`'s canonical order, not the order the file wrote -
        // which is itself worth rendering, since that is the order zecd works in.
        assert!(
            first.contains("privacy_policy = \"FullPrivacy\""),
            "{first}"
        );
        assert!(
            first.contains("enabled = [\"sapling\", \"orchard\"]"),
            "{first}"
        );
        assert!(first.contains("readiness = \"connected\""), "{first}");
    }

    /// Every value the file left unset appears, filled in by this build - the whole point of the
    /// command, and what makes a cross-version diff meaningful.
    #[test]
    fn defaults_the_file_never_mentions_are_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let out = render(&resolve_from("network = \"test\"\n", dir.path()));
        for defaulted in [
            "privacy_policy = \"AllowRevealedRecipients\"",
            "trusted_confirmations = 3",
            "untrusted_confirmations = 10",
            "work_queue = 100",
            "interval_secs = 20",
            "readiness = \"synced\"",
            "transparent = false",
            "cache_proving_key = true",
        ] {
            assert!(out.contains(defaulted), "missing {defaulted:?} in:\n{out}");
        }
        // The resolved endpoint rides alongside the token it derives from.
        assert!(
            out.contains("server = \"zebra\"  # zebra-rpc 127.0.0.1:18234"),
            "{out}"
        );
    }

    /// Credentials are named, never printed - `zecd config show` output is the kind of thing
    /// that gets pasted into an issue, and the RPC password is spend authority.
    #[test]
    fn secrets_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let out = render(&resolve_from(
            "network = \"test\"\n\
             [rpc]\nuser = \"alice\"\npassword = \"hunter2\"\nauth = [\"bob:ab$cd\"]\n\
             [zebra]\nrpc_user = \"zu\"\nrpc_password = \"zp\"\n",
            dir.path(),
        ));
        for secret in ["hunter2", "bob:ab$cd", "zp"] {
            assert!(!out.contains(secret), "leaked {secret:?}:\n{out}");
        }
        assert!(out.contains("# user, password = <redacted>"), "{out}");
        assert!(out.contains("# auth = <redacted>"), "{out}");
        assert!(
            out.contains("# rpc_user, rpc_password = <redacted>"),
            "{out}"
        );
        // Commented out rather than a parsable placeholder: a redacted value that *parses* would
        // become a real, wrong credential if the output were ever deployed.
        assert!(!out.contains("password = \"<redacted>\""), "{out}");
    }

    /// A wallet entry stands on its own: every pool setting appears resolved under the wallet,
    /// so reading it never means mentally applying the global `[pools]` defaults.

    #[test]
    fn per_wallet_backend_overrides_render_and_re_resolve() {
        // The renderer's schema contract on the per-wallet endpoint keys: what it emits must be
        // a config `resolve` accepts, and rendering it again must reproduce it byte for byte.
        let dir = tempfile::tempdir().unwrap();
        let cfg = resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [backend]\nserver = \"zebra\"\n\
                 [wallets.default]\n\
                 [wallets.replica]\nserver = \"https://lwd.example:9067\"\n\
                 tls = \"yes\"\ntls_roots = \"webpki\"\n\
                 assume_transparent_in_compact_blocks = true\n",
                dir.path()
            ),
            dir.path(),
        );
        let out = render(&cfg);

        let replica = out
            .split("[wallets.replica]")
            .nth(1)
            .expect("the wallet table");
        assert!(
            replica.contains("server = \"https://lwd.example:9067\""),
            "{replica}"
        );
        assert!(replica.contains("tls = \"yes\""), "{replica}");
        assert!(replica.contains("tls_roots = \"webpki\""), "{replica}");
        assert!(
            replica.contains("assume_transparent_in_compact_blocks = true"),
            "{replica}"
        );

        // A wallet with no overrides emits no endpoint keys - it falls back to [backend].
        let default = out
            .split("[wallets.default]")
            .nth(1)
            .and_then(|rest| rest.split("[wallets.replica]").next())
            .expect("the default wallet table");
        assert!(!default.contains("server ="), "{default}");
        assert!(!default.contains("tls ="), "{default}");

        assert_eq!(out, render(&resolve_from(&out, dir.path())));
    }

    #[test]
    fn wallet_entries_carry_their_resolved_pool_settings() {
        let dir = tempfile::tempdir().unwrap();
        let out = render(&resolve_from(
            &format!(
                "network = \"test\"\ndatadir = {:?}\n\
                 [pools]\ntransparent = true\ntransparent_gap_limit = 20\n\
                 [wallets.exchange]\ntransparent_gap_limit = 1000\ntransparent_initial_scan = 70000\n",
                dir.path()
            ),
            dir.path(),
        ));
        let wallet = out
            .split("[wallets.exchange]")
            .nth(1)
            .expect("the wallet table");
        assert!(wallet.contains("transparent = true"), "{wallet}");
        assert!(wallet.contains("transparent_gap_limit = 1000"), "{wallet}");
        assert!(
            wallet.contains("transparent_initial_scan = 70000"),
            "{wallet}"
        );
    }
}
