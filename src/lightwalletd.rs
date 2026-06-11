//! lightwalletd connection management. Ported from `zcash-devtool/src/remote.rs`, keeping
//! direct connections only. TLS is used for remote hosts and skipped for localhost, but can
//! be forced on/off explicitly (e.g. a co-located plaintext lightwalletd reached by service
//! name in docker-compose). No Tor/SOCKS.

use std::borrow::Cow;
use std::time::Duration;

use anyhow::anyhow;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

use crate::network::ZNetwork;

/// Which set of root certificates to trust for TLS connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TlsRoots {
    /// OS trust store (honors `SSL_CERT_FILE`). Works behind TLS-intercepting proxies and with
    /// local/corporate CAs. Default.
    #[default]
    Native,
    /// Embedded Mozilla root bundle (webpki-roots). Good for minimal containers, but won't
    /// trust private/proxy CAs.
    Webpki,
}

impl TlsRoots {
    pub fn parse(s: &str) -> anyhow::Result<TlsRoots> {
        match s.trim().to_ascii_lowercase().as_str() {
            "native" | "system" => Ok(TlsRoots::Native),
            "webpki" | "mozilla" => Ok(TlsRoots::Webpki),
            other => Err(anyhow!("invalid tls_roots '{other}', expected 'native' or 'webpki'")),
        }
    }
}

/// Parse a `[lightwalletd] tls` setting into a force-TLS override: `auto` (None) uses the
/// localhost heuristic; `yes`/`no` force it.
pub fn parse_tls_mode(s: &str) -> anyhow::Result<Option<bool>> {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(None),
        "yes" | "true" | "on" | "tls" => Ok(Some(true)),
        "no" | "false" | "off" | "plaintext" => Ok(Some(false)),
        other => Err(anyhow!("invalid tls '{other}', expected 'auto', 'yes', or 'no'")),
    }
}

/// A resolved lightwalletd endpoint.
#[derive(Clone, Debug)]
pub struct Server {
    host: Cow<'static, str>,
    port: u16,
    roots: TlsRoots,
    /// `Some(true/false)` forces TLS on/off; `None` uses the localhost heuristic.
    force_tls: Option<bool>,
}

impl Server {
    fn new(host: Cow<'static, str>, port: u16, roots: TlsRoots, force_tls: Option<bool>) -> Self {
        Server { host, port, roots, force_tls }
    }

    fn use_tls(&self) -> bool {
        self.force_tls.unwrap_or_else(|| {
            !matches!(self.host.as_ref(), "localhost" | "127.0.0.1" | "::1")
        })
    }

    fn endpoint(&self) -> String {
        format!(
            "{}://{}:{}",
            if self.use_tls() { "https" } else { "http" },
            self.host,
            self.port
        )
    }

    pub fn describe(&self) -> String {
        format!("{}:{} (tls={})", self.host, self.port, self.use_tls())
    }

    /// Open a gRPC connection to this lightwalletd server, bounding the whole dial (including
    /// the TLS handshake) with `timeout` so a hung/black-holed endpoint can't stall the caller.
    pub async fn connect_timeout(
        &self,
        timeout: Duration,
    ) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
        // HTTP/2 keepalive: a peer that accepted the connection but stopped responding (hung
        // process, black-holed path) fails every in-flight RPC and stream within
        // interval+timeout, instead of stalling them forever - TCP alone can't detect this
        // (the kernel keeps ACKing for a stopped process). This is the systemic backstop for
        // the long-lived channel; the actor additionally puts explicit deadlines on its
        // critical unary calls.
        let channel = Channel::from_shared(self.endpoint())?
            .http2_keep_alive_interval(Duration::from_secs(15))
            .keep_alive_timeout(Duration::from_secs(5))
            .keep_alive_while_idle(true);
        let channel = if self.use_tls() {
            let tls = ClientTlsConfig::new()
                .domain_name(self.host.to_string())
                .assume_http2(true);
            let tls = match self.roots {
                TlsRoots::Native => tls.with_native_roots(),
                TlsRoots::Webpki => tls.with_webpki_roots(),
            };
            channel.tls_config(tls)?
        } else {
            channel
        };
        let connected = tokio::time::timeout(timeout, channel.connect())
            .await
            .map_err(|_| anyhow!("connect to {} timed out after {timeout:?}", self.describe()))??;
        Ok(CompactTxStreamerClient::new(connected))
    }

    /// Open a gRPC connection with a default dial timeout. Convenience for the network
    /// integration tests; production callers use [`connect_timeout`](Server::connect_timeout).
    #[cfg(test)]
    pub async fn connect(&self) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
        self.connect_timeout(Duration::from_secs(30)).await
    }
}

// Presets as (host, port). TLS roots / force-mode are attached at resolve time.
const ECC_TESTNET: &[(&str, u16)] = &[("lightwalletd.testnet.electriccoin.co", 9067)];
const YWALLET_MAINNET: &[(&str, u16)] =
    &[("lwd1.zcash-infra.com", 9067), ("lwd2.zcash-infra.com", 9067)];
const ZEC_ROCKS_MAINNET: &[(&str, u16)] = &[("zec.rocks", 443)];
const ZEC_ROCKS_TESTNET: &[(&str, u16)] = &[("testnet.zec.rocks", 443)];

/// Resolve a single server token (`ecc` | `ywallet` | `zecrocks` | `host:port[,host:port]`) for
/// the given network into an ordered, non-empty list of [`Server`]s. Multi-endpoint presets and
/// comma-separated host lists expand to all of their endpoints (the first is the primary). A
/// `host:port` may carry an `http://`/`https://` scheme to force that endpoint's TLS mode,
/// overriding the global `tls` setting (e.g. a plaintext local node + TLS public fallbacks).
pub fn resolve(
    server: &str,
    network: ZNetwork,
    roots: TlsRoots,
    force_tls: Option<bool>,
) -> anyhow::Result<Vec<Server>> {
    // The named presets are public mainnet/testnet infrastructure; regtest has none, so a
    // regtest deployment must give an explicit `host:port` (handled by `parse_host_list`).
    let preset: Option<&[(&str, u16)]> = match (server, network) {
        ("ecc", ZNetwork::Test) => Some(ECC_TESTNET),
        ("ecc", _) => None,
        ("ywallet", ZNetwork::Main) => Some(YWALLET_MAINNET),
        ("ywallet", _) => None,
        ("zecrocks", ZNetwork::Main) => Some(ZEC_ROCKS_MAINNET),
        ("zecrocks", ZNetwork::Test) => Some(ZEC_ROCKS_TESTNET),
        ("zecrocks", _) => None,
        _ => return parse_host_list(server, roots, force_tls),
    };

    match preset {
        // Preset consts are non-empty by construction, so the result is non-empty.
        Some(entries) => Ok(entries
            .iter()
            .map(|&(host, port)| Server::new(Cow::Borrowed(host), port, roots, force_tls))
            .collect()),
        None => Err(anyhow!(
            "lightwalletd preset '{server}' does not serve {}",
            network.name()
        )),
    }
}

/// Resolve an ordered list of server tokens (each a preset name, a `host:port`, or a
/// comma-separated `host:port` list) into one flat, ordered, non-empty list of [`Server`]s.
pub fn resolve_all(
    servers: &[String],
    network: ZNetwork,
    roots: TlsRoots,
    force_tls: Option<bool>,
) -> anyhow::Result<Vec<Server>> {
    let mut out = Vec::new();
    for token in servers {
        out.extend(resolve(token, network, roots, force_tls)?);
    }
    if out.is_empty() {
        return Err(anyhow!("no lightwalletd servers configured"));
    }
    Ok(out)
}

fn parse_host_list(s: &str, roots: TlsRoots, force_tls: Option<bool>) -> anyhow::Result<Vec<Server>> {
    let mut servers = Vec::new();
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // An optional `http://`/`https://` scheme sets TLS per endpoint, overriding the global
        // `tls` setting - so a plaintext local node and TLS public fallbacks can share one list.
        let (force, rest) = if let Some(r) = entry.strip_prefix("https://") {
            (Some(true), r)
        } else if let Some(r) = entry.strip_prefix("http://") {
            (Some(false), r)
        } else {
            (force_tls, entry)
        };
        let (host, port_str) = rest
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid lightwalletd address '{entry}', expected host:port"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("invalid port in '{entry}'"))?;
        servers.push(Server::new(Cow::Owned(host.to_string()), port, roots, force));
    }
    if servers.is_empty() {
        return Err(anyhow!("no lightwalletd hosts in '{s}'"));
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_presets_and_custom() {
        let s = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None).unwrap();
        assert_eq!(s[0].host.as_ref(), "testnet.zec.rocks");
        assert!(s[0].use_tls());
        let s = resolve("zecrocks", ZNetwork::Main, TlsRoots::Native, None).unwrap();
        assert_eq!(s[0].host.as_ref(), "zec.rocks");
        // localhost auto -> plaintext
        let s = resolve("127.0.0.1:9067", ZNetwork::Test, TlsRoots::Native, None).unwrap();
        assert!(!s[0].use_tls());
        // forced plaintext for a co-located lightwalletd reached by service name
        let s = resolve("lightwalletd:9067", ZNetwork::Test, TlsRoots::Native, Some(false)).unwrap();
        assert!(!s[0].use_tls());
        // forced TLS even for localhost
        let s = resolve("127.0.0.1:443", ZNetwork::Main, TlsRoots::Native, Some(true)).unwrap();
        assert!(s[0].use_tls());
        assert!(resolve("ecc", ZNetwork::Main, TlsRoots::Native, None).is_err());
    }

    #[test]
    fn single_host_unchanged() {
        let s = resolve("127.0.0.1:9067", ZNetwork::Test, TlsRoots::Native, None).unwrap();
        assert_eq!(s.len(), 1);
        assert!(!s[0].use_tls());
    }

    #[test]
    fn resolves_multi_host() {
        let s = resolve("a.example:9067,b.example:443", ZNetwork::Test, TlsRoots::Native, None)
            .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host.as_ref(), "a.example");
        assert_eq!(s[0].port, 9067);
        assert_eq!(s[1].host.as_ref(), "b.example");
        assert_eq!(s[1].port, 443);
    }

    #[test]
    fn resolves_preset_returns_all_endpoints() {
        // ywallet mainnet has two endpoints; both must be returned (old resolve dropped the 2nd).
        let s = resolve("ywallet", ZNetwork::Main, TlsRoots::Native, None).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host.as_ref(), "lwd1.zcash-infra.com");
        assert_eq!(s[1].host.as_ref(), "lwd2.zcash-infra.com");
    }

    #[test]
    fn multi_host_tolerates_whitespace_and_trailing_comma() {
        let s = resolve("a:1 , b:2 ,", ZNetwork::Test, TlsRoots::Native, None).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host.as_ref(), "a");
        assert_eq!(s[1].host.as_ref(), "b");
    }

    #[test]
    fn empty_host_list_errors() {
        assert!(resolve(" , ", ZNetwork::Test, TlsRoots::Native, None).is_err());
        assert!(resolve(",", ZNetwork::Test, TlsRoots::Native, None).is_err());
    }

    #[test]
    fn scheme_prefix_sets_tls_per_server() {
        // Global tls=auto (None); scheme prefixes pick TLS per endpoint.
        let s = resolve(
            "http://lightwalletd:9067,https://zec.rocks:443",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host.as_ref(), "lightwalletd");
        assert!(!s[0].use_tls()); // http:// => plaintext even though it's a remote-looking host
        assert_eq!(s[1].host.as_ref(), "zec.rocks");
        assert!(s[1].use_tls()); // https:// => TLS
    }

    #[test]
    fn scheme_prefix_overrides_global_tls() {
        // Even with a global force (tls="no"), an explicit https:// forces TLS for that endpoint.
        let s = resolve(
            "lightwalletd:9067,https://zec.rocks:443",
            ZNetwork::Main,
            TlsRoots::Native,
            Some(false),
        )
        .unwrap();
        assert!(!s[0].use_tls()); // no scheme -> global force (plaintext)
        assert!(s[1].use_tls()); // scheme overrides to TLS
    }

    #[test]
    fn resolve_all_flattens() {
        let tokens = vec!["127.0.0.1:9067".to_string(), "zecrocks".to_string()];
        let s = resolve_all(&tokens, ZNetwork::Main, TlsRoots::Native, None).unwrap();
        assert_eq!(s.len(), 2); // 127.0.0.1:9067 + zec.rocks
        assert_eq!(s[0].host.as_ref(), "127.0.0.1");
        assert_eq!(s[1].host.as_ref(), "zec.rocks");
        assert!(resolve_all(&[], ZNetwork::Main, TlsRoots::Native, None).is_err());
    }

    #[test]
    fn tls_mode_parsing() {
        assert_eq!(parse_tls_mode("auto").unwrap(), None);
        assert_eq!(parse_tls_mode("no").unwrap(), Some(false));
        assert_eq!(parse_tls_mode("yes").unwrap(), Some(true));
        assert!(parse_tls_mode("maybe").is_err());
    }

    // --- Network integration tests (hit the public zecrocks/ECC testnet lightwalletd) ---
    // Run with: cargo test -- --include-ignored

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_get_latest_block() {
        use zcash_client_backend::proto::service;
        let server = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut client = server.connect().await.expect("connect to testnet.zec.rocks");
        let tip = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .expect("get_latest_block")
            .into_inner();
        assert!(tip.height > 2_000_000, "unexpected testnet height {}", tip.height);
        assert_eq!(tip.hash.len(), 32, "block hash must be 32 bytes");
    }

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_lightd_info_and_treestate() {
        use zcash_client_backend::proto::service;
        let server = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut client = server.connect().await.expect("connect");

        let info = client
            .get_lightd_info(service::Empty {})
            .await
            .expect("get_lightd_info")
            .into_inner();
        assert!(!info.vendor.is_empty());
        assert!(info.block_height > 2_000_000);
        assert!(info.chain_name.contains("test"), "unexpected chain_name {}", info.chain_name);

        let h = info.block_height - 100;
        let ts = client
            .get_tree_state(service::BlockId { height: h, hash: vec![] })
            .await
            .expect("get_tree_state")
            .into_inner();
        assert_eq!(ts.height, h);
        ts.to_chain_state().expect("tree state converts to chain state");
    }

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn failover_skips_dead_first_endpoint() {
        use zcash_client_backend::proto::service;
        // A closed local port as the primary, with the live testnet endpoint as fallback.
        let servers =
            resolve("127.0.0.1:1,testnet.zec.rocks:443", ZNetwork::Test, TlsRoots::Native, None)
                .unwrap();
        assert_eq!(servers.len(), 2);
        let timeout = Duration::from_secs(10);
        // The primary must fail (and fail fast), so the actor would move on.
        assert!(servers[0].connect_timeout(timeout).await.is_err());
        // The fallback must connect - this is the endpoint failover lands on.
        let mut client = servers[1]
            .connect_timeout(timeout)
            .await
            .expect("failover endpoint connects");
        let tip = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .expect("get_latest_block")
            .into_inner();
        assert!(tip.height > 2_000_000, "unexpected testnet height {}", tip.height);
    }

    #[tokio::test]
    #[ignore = "hits zec.rocks (mainnet) over the network"]
    async fn mainnet_zecrocks_get_latest_block() {
        use zcash_client_backend::proto::service;
        let server = resolve("zecrocks", ZNetwork::Main, TlsRoots::Native, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut client = server.connect().await.expect("connect to zec.rocks");
        let tip = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .expect("get_latest_block")
            .into_inner();
        assert!(tip.height > 2_500_000, "unexpected mainnet height {}", tip.height);
    }
}
