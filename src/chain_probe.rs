//! `zecd chain info`: dial the configured upstream and report its chain tip, without a wallet.
//!
//! This exists because there was no way to answer two questions before a wallet existed.
//! [`crate::config_check`] is deliberately offline - it reports what the daemon *would* refuse,
//! and never opens a socket - so "can this deployment actually reach its backend?" had no
//! answer short of starting the daemon, which needs a wallet to start at all. And a caller that
//! wants to pin a birthday alongside a seed it generated itself needs the tip *before*
//! [`crate::init::init_wallet`] runs, since that is what records the birthday.
//!
//! Like `config check` and `derive-address`, it is strictly read-only: no datadir lock (so it
//! runs against a live deployment), no wallet database, no cookie file. The only side effect is
//! the network round trip itself.

use std::time::{Duration, Instant};

use anyhow::Context;

use crate::chain::{ChainSource, UnsupportedUpgrade};
use crate::config::AppConfig;
use crate::network::ZNetwork;

/// What the upstream reported, plus the conclusions a caller would otherwise re-derive.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainInfo {
    /// The endpoint actually dialed, as `Server::describe` renders it.
    pub server: String,
    /// The network this configuration is for.
    pub network: ZNetwork,
    /// Chain name the upstream reports (`main`, `test`, `regtest`, or something unrecognized).
    pub chain_name: String,
    /// Whether the upstream's chain matches `network`. `None` when the chain name is not one
    /// this build recognizes, which is a "cannot tell", not a pass.
    pub network_matches: Option<bool>,
    /// Height of the upstream's current tip.
    pub tip_height: u32,
    /// Hash of the upstream's current tip, in display (big-endian) hex. `None` when the
    /// upstream reported no hash, or one that is not 32 bytes.
    pub tip_hash: Option<String>,
    /// The birthday [`crate::init`] would record for a freshly generated wallet at this tip.
    pub suggested_birthday: u32,
    /// Consensus branch ID in force at the tip, when the upstream reports one.
    pub tip_branch_id: Option<u32>,
    /// Network upgrades the upstream knows of that this build does not - the outdated-build
    /// signal. Empty is the healthy case.
    pub unsupported_upgrades: Vec<UnsupportedUpgrade>,
    /// How long the dial plus both queries took.
    pub elapsed: Duration,
}

impl ChainInfo {
    /// Whether this build understands every upgrade the upstream reports, and is on the right
    /// chain - i.e. whether a wallet against this endpoint would sync.
    pub fn is_usable(&self) -> bool {
        self.network_matches != Some(false) && self.unsupported_upgrades.is_empty()
    }
}

/// Dial the upstream and report its tip.
///
/// `server_override` probes an endpoint other than the configured one, using the same token
/// grammar as `[backend] server` - for checking a candidate before committing it to a config.
pub async fn probe(config: &AppConfig, server_override: Option<&str>) -> anyhow::Result<ChainInfo> {
    // An override is applied by resolving a copy of the configuration with the token swapped,
    // rather than by a second resolution path: the endpoint then carries the same `[zebra]`
    // credentials, cleartext policy and TLS settings the daemon would give it, so what this
    // probes is what a daemon on that token would dial.
    let token = server_override.unwrap_or(&config.backend.server);
    let resolved;
    let config = match server_override {
        None => config,
        Some(token) => {
            let mut overridden = config.clone();
            token.clone_into(&mut overridden.backend.server);
            resolved = overridden;
            &resolved
        }
    };
    let server = crate::backend::resolve_configured(config)
        .with_context(|| format!("resolving backend server {token:?}"))?;
    // The same no-network refusals the daemon applies, so an endpoint this build would never
    // dial fails here with that reason rather than as a connection error.
    server.preflight()?;

    let started = Instant::now();
    let mut source = server
        .connect_timeout(Duration::from_secs(config.backend.connect_timeout_secs))
        .await?;
    let info = source.server_info().await.context("fetching server info")?;
    let tip = source.latest_block().await.context("fetching chain tip")?;
    let elapsed = started.elapsed();

    // `ChainTip::height` is u64 and `hash` is internal byte order, possibly absent - the same
    // narrowing and reversal the actor applies when it publishes a tip.
    let tip_height = u32::try_from(tip.height).with_context(|| {
        format!(
            "upstream reported an out-of-range tip height {}",
            tip.height
        )
    })?;
    let tip_hash = (tip.hash.len() == 32).then(|| {
        let mut h = tip.hash.clone();
        h.reverse();
        hex::encode(h)
    });
    Ok(ChainInfo {
        server: server.describe(),
        network: config.network,
        network_matches: crate::wallet::actor::chain_name_is_main(&info.chain_name)
            .map(|upstream_is_main| upstream_is_main == matches!(config.network, ZNetwork::Main)),
        chain_name: info.chain_name.clone(),
        tip_height,
        tip_hash,
        suggested_birthday: crate::init::fresh_wallet_birthday(tip_height),
        tip_branch_id: info.tip_branch_id,
        unsupported_upgrades: crate::chain::unsupported_upgrades(&info),
        elapsed,
    })
}

/// `zecd chain-info`: the CLI shell around [`probe`].
///
/// Streams follow `config check`: the report goes to stdout (so `--json` can be piped
/// straight into a tool), and any verdict about it goes to stderr. Exits non-zero when the
/// endpoint is unusable - a wrong chain, or upgrades this build does not know - so a
/// deployment check can gate on it rather than parse the output.
#[cfg(feature = "cli")]
pub async fn run(config: &AppConfig, args: &crate::config::ChainInfoArgs) -> anyhow::Result<()> {
    let info = probe(config, args.server.as_deref()).await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&json_report(&info))?);
    } else {
        println!("server            {}", info.server);
        println!("network           {}", info.network.name());
        println!("chain             {}", info.chain_name);
        println!("tip height        {}", info.tip_height);
        println!(
            "tip hash          {}",
            info.tip_hash.as_deref().unwrap_or("(not reported)")
        );
        println!("birthday for new  {}", info.suggested_birthday);
        if let Some(id) = info.tip_branch_id {
            println!("branch id         {id:08x}");
        }
        println!("round trip        {} ms", info.elapsed.as_millis());
    }

    if info.network_matches == Some(false) {
        anyhow::bail!(
            "upstream serves chain '{}' but this configuration is for '{}'",
            info.chain_name,
            info.network.name()
        );
    }
    if info.network_matches.is_none() {
        eprintln!(
            "warning: upstream reported unrecognized chain '{}'; cannot confirm it matches '{}'",
            info.chain_name,
            info.network.name()
        );
    }
    if !info.unsupported_upgrades.is_empty() {
        for u in &info.unsupported_upgrades {
            eprintln!(
                "{}: upstream reports network upgrade {} (branch id {:08x}){} that this zecd \
                 build does not know",
                if u.active { "error" } else { "warning" },
                u.name,
                u.branch_id,
                match u.activation_height {
                    Some(h) => format!(" at height {h}"),
                    None => String::new(),
                },
            );
        }
        if info.unsupported_upgrades.iter().any(|u| u.active) {
            anyhow::bail!(
                "this zecd build cannot follow the upstream's current consensus rules; update \
                 zecd before syncing a wallet against it"
            );
        }
    }
    eprintln!("OK: reachable, chain matches, consensus rules understood");
    Ok(())
}

/// The `--json` shape. Written out by hand rather than derived, so the field names are a
/// deliberate contract rather than whatever the Rust struct happens to be called.
#[cfg(feature = "cli")]
fn json_report(info: &ChainInfo) -> serde_json::Value {
    serde_json::json!({
        "server": info.server,
        "network": info.network.name(),
        "chain": info.chain_name,
        "network_matches": info.network_matches,
        "tip_height": info.tip_height,
        "tip_hash": info.tip_hash,
        "suggested_birthday": info.suggested_birthday,
        "branch_id": info.tip_branch_id.map(|id| format!("{id:08x}")),
        "unsupported_upgrades": info
            .unsupported_upgrades
            .iter()
            .map(|u| serde_json::json!({
                "name": u.name,
                "branch_id": format!("{:08x}", u.branch_id),
                "activation_height": u.activation_height,
                "active": u.active,
            }))
            .collect::<Vec<_>>(),
        "usable": info.is_usable(),
        "elapsed_ms": info.elapsed.as_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::UnsupportedUpgrade;

    fn info(network_matches: Option<bool>, upgrades: Vec<UnsupportedUpgrade>) -> ChainInfo {
        ChainInfo {
            server: "test".into(),
            network: ZNetwork::Main,
            chain_name: "main".into(),
            network_matches,
            tip_height: 100,
            tip_hash: None,
            suggested_birthday: 0,
            tip_branch_id: None,
            unsupported_upgrades: upgrades,
            elapsed: Duration::ZERO,
        }
    }

    fn upgrade(active: bool) -> UnsupportedUpgrade {
        UnsupportedUpgrade {
            branch_id: 1,
            name: "future".into(),
            activation_height: Some(5),
            active,
        }
    }

    /// An unrecognized chain name is "cannot tell", not "wrong" - refusing on it would make the
    /// probe useless against any chain this build has no name for (a custom regtest, say), and
    /// the CLI warns instead. But a *pending* upgrade this build does not know is also not a
    /// refusal: the wallet syncs fine until it activates, which is the whole point of warning
    /// early rather than at activation.
    #[test]
    fn usability_refuses_only_a_wrong_chain_or_an_active_unknown_upgrade() {
        assert!(info(Some(true), vec![]).is_usable());
        assert!(
            info(None, vec![]).is_usable(),
            "unrecognized chain is not a refusal"
        );
        assert!(!info(Some(false), vec![]).is_usable(), "wrong chain");
        assert!(
            !info(Some(true), vec![upgrade(true)]).is_usable(),
            "an active upgrade this build cannot follow"
        );
    }

    /// The probe reports the birthday `init` would record, rather than re-deriving the policy,
    /// so the two cannot drift. On a chain shorter than the margin it must clamp rather than
    /// wrap - a fresh regtest chain is exactly that case.
    #[test]
    fn suggested_birthday_matches_init_and_clamps_on_a_short_chain() {
        assert_eq!(
            crate::init::fresh_wallet_birthday(1_000),
            1_000 - crate::init::FRESH_WALLET_BIRTHDAY_MARGIN
        );
        assert_eq!(crate::init::fresh_wallet_birthday(0), 0);
        assert_eq!(crate::init::fresh_wallet_birthday(5), 0);
    }
}
