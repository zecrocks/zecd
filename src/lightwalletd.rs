//! Upstream-endpoint management: parsing/resolving the `[lightwalletd] servers` list and
//! dialing its entries. Ported from `zcash-devtool/src/remote.rs`. TLS is used for remote
//! hosts and skipped for localhost (and `.onion`), but can be forced on/off explicitly
//! (e.g. a co-located plaintext lightwalletd reached by service name in docker-compose).
//!
//! Two endpoint kinds share the one ordered failover list (see [`ServerKind`]):
//! local zebrad JSON-RPC endpoints (`zebra://host:port`, or the `zebra` preset - the
//! default) and lightwalletd gRPC endpoints (`host:port`, presets, `http(s)://` prefixes) -
//! so `servers = ["zebra://127.0.0.1:8234", "zec.rocks:443"]` gives a local full node with
//! a public lightwalletd fallback. Connecting yields an [`AnySource`] either way; everything
//! above this module is backend-agnostic.
//!
//! Connections can optionally be routed through a SOCKS5 proxy (`[lightwalletd] connection`),
//! which covers Tor, Nym, and any other SOCKS5 proxy - see [`parse_connection_mode`]. The proxy,
//! like the TLS settings, is attached to every resolved [`Server`] so no connection can silently
//! bypass it. `zebra://` endpoints are for local nodes and refuse to combine with a proxy
//! (see [`resolve_all`]).

use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::anyhow;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

use crate::chain::lwd::LwdSource;
use crate::chain::zebra::{ZebraAuth, ZebraSource};
use crate::chain::AnySource;
use crate::network::ZNetwork;
use crate::socks::SocksConnector;

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
            other => Err(anyhow!(
                "invalid tls_roots '{other}', expected 'native' or 'webpki'"
            )),
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
        other => Err(anyhow!(
            "invalid tls '{other}', expected 'auto', 'yes', or 'no'"
        )),
    }
}

/// Tor's conventional local SOCKS5 listener, used as the proxy when `connection = "tor"`.
const TOR_SOCKS_DEFAULT: &str = "127.0.0.1:9050";

/// Parse a `[lightwalletd] connection` setting into an optional SOCKS5 proxy address that every
/// lightwalletd connection should be dialed through. Recognised forms:
///
/// - `direct` - no proxy; dial endpoints directly (the default).
/// - `tor` - route through Tor's default local SOCKS port (`127.0.0.1:9050`). zecd has no
///   built-in Tor client (unlike zcash-devtool), so this is just a convenience alias for the
///   standard Tor proxy; run a `tor` daemon alongside zecd.
/// - `socks5://<host>:<port>` - route through an explicit SOCKS5 proxy (Tor on a non-default
///   port, Nym, etc.).
pub fn parse_connection_mode(s: &str) -> anyhow::Result<Option<SocketAddr>> {
    let s = s.trim();
    match s.to_ascii_lowercase().as_str() {
        "direct" | "" => Ok(None),
        "tor" => Ok(Some(parse_socks_addr(TOR_SOCKS_DEFAULT)?)),
        lower if lower.starts_with("socks5://") => {
            // Slice the original (not the lowercased copy) so the address keeps its case.
            Ok(Some(parse_socks_addr(&s["socks5://".len()..])?))
        }
        _ => Err(anyhow!(
            "invalid connection '{s}', expected 'direct', 'tor', or 'socks5://<host>:<port>'"
        )),
    }
}

fn parse_socks_addr(addr: &str) -> anyhow::Result<SocketAddr> {
    addr.trim()
        .parse()
        .map_err(|_| anyhow!("invalid SOCKS5 proxy address '{addr}', expected <ip>:<port>"))
}

/// What protocol a resolved endpoint speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerKind {
    /// A lightwalletd `CompactTxStreamer` gRPC endpoint.
    Lightwalletd,
    /// A local zebrad JSON-RPC endpoint (`zebra://host:port`), plaintext HTTP.
    ZebraRpc,
}

/// A resolved upstream endpoint (lightwalletd or local zebrad).
#[derive(Clone, Debug)]
pub struct Server {
    host: Cow<'static, str>,
    port: u16,
    kind: ServerKind,
    /// Needed by the zebra backend to parse raw blocks (consensus branch IDs).
    network: ZNetwork,
    roots: TlsRoots,
    /// `Some(true/false)` forces TLS on/off; `None` uses the localhost heuristic.
    /// lightwalletd only; `zebra://` endpoints are always plaintext HTTP.
    force_tls: Option<bool>,
    /// When set, every connection to this endpoint is dialed through this SOCKS5 proxy.
    proxy: Option<SocketAddr>,
    /// zebrad RPC credentials (`[zebra]` config); ignored by lightwalletd endpoints.
    zebra_auth: ZebraAuth,
}

impl Server {
    #[allow(clippy::too_many_arguments)]
    fn new(
        host: Cow<'static, str>,
        port: u16,
        kind: ServerKind,
        network: ZNetwork,
        roots: TlsRoots,
        force_tls: Option<bool>,
        proxy: Option<SocketAddr>,
    ) -> Self {
        Server {
            host,
            port,
            kind,
            network,
            roots,
            force_tls,
            proxy,
            zebra_auth: ZebraAuth::default(),
        }
    }

    fn use_tls(&self) -> bool {
        self.force_tls.unwrap_or_else(|| {
            // localhost never has a cert; `.onion` is encrypted by Tor itself. Everything else
            // is treated as a remote host that needs TLS.
            !matches!(self.host.as_ref(), "localhost" | "127.0.0.1" | "::1")
                && !self.host.ends_with(".onion")
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
        let base = match self.kind {
            ServerKind::Lightwalletd => {
                format!("{}:{} (tls={})", self.host, self.port, self.use_tls())
            }
            ServerKind::ZebraRpc => format!("zebra-rpc {}:{}", self.host, self.port),
        };
        match self.proxy {
            Some(proxy) => format!("{} (socks={proxy})", base.trim_end()),
            None => base,
        }
    }

    /// Connect to this endpoint, bounding the whole dial with `timeout` so a hung/black-holed
    /// endpoint can't stall the caller. For lightwalletd that is the TCP/TLS connect; for a
    /// zebra endpoint it is the client construction (cookie read) plus one
    /// `getblockchaininfo` round-trip, the closest analog of a dial.
    pub async fn connect_timeout(&self, timeout: Duration) -> anyhow::Result<AnySource> {
        match self.kind {
            ServerKind::Lightwalletd => {
                let client = self.connect_lwd_timeout(timeout).await?;
                Ok(AnySource::Lwd(LwdSource::new(client)))
            }
            ServerKind::ZebraRpc => {
                let connect =
                    ZebraSource::connect(&self.host, self.port, &self.zebra_auth, self.network);
                let source = tokio::time::timeout(timeout, connect).await.map_err(|_| {
                    anyhow!("connect to {} timed out after {timeout:?}", self.describe())
                })??;
                Ok(AnySource::Zebra(source))
            }
        }
    }

    /// Open a gRPC connection to this lightwalletd server, bounding the whole dial (including
    /// the TLS handshake) with `timeout`.
    async fn connect_lwd_timeout(
        &self,
        timeout: Duration,
    ) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
        // HTTP/2 keepalive: a peer that accepted the connection but stopped responding (hung
        // process, black-holed path) fails every in-flight RPC and stream within
        // interval+timeout, instead of stalling them forever - TCP alone can't detect this
        // (the kernel keeps ACKing for a stopped process). This is the systemic backstop for
        // the long-lived channel; the actor additionally puts explicit deadlines on its
        // critical unary calls. TCP keepalive complements it below the HTTP/2 layer: it
        // detects a dead L4 path (host suspend, NAT rebind, silently dropped conntrack
        // entries) and keeps idle NAT/firewall mappings alive between syncs.
        let endpoint = Channel::from_shared(self.endpoint())?
            .tcp_keepalive(Some(Duration::from_secs(15)))
            .http2_keep_alive_interval(Duration::from_secs(15))
            .keep_alive_timeout(Duration::from_secs(5))
            .keep_alive_while_idle(true);
        let endpoint = if self.use_tls() {
            let tls = ClientTlsConfig::new()
                .domain_name(self.host.to_string())
                .assume_http2(true);
            let tls = match self.roots {
                TlsRoots::Native => tls.with_native_roots(),
                TlsRoots::Webpki => tls.with_webpki_roots(),
            };
            endpoint.tls_config(tls)?
        } else {
            endpoint
        };
        // Routing through a SOCKS5 proxy supplies tonic a custom connector; tonic still layers
        // the `tls_config` above over the proxied stream, so remote endpoints stay TLS-encrypted
        // end to end (the proxy only sees ciphertext). Without a proxy we dial directly.
        let connect = async {
            match self.proxy {
                Some(proxy) => {
                    endpoint
                        .connect_with_connector(SocksConnector::new(proxy))
                        .await
                }
                None => endpoint.connect().await,
            }
        };
        let connected = tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| anyhow!("connect to {} timed out after {timeout:?}", self.describe()))??;
        Ok(CompactTxStreamerClient::new(connected))
    }

    /// Connect with a default dial timeout. Convenience for the network integration tests;
    /// production callers use [`connect_timeout`](Server::connect_timeout).
    #[cfg(test)]
    pub async fn connect(&self) -> anyhow::Result<AnySource> {
        self.connect_timeout(Duration::from_secs(30)).await
    }
}

/// Attach zebrad RPC credentials (the `[zebra]` config section) to every `zebra://` endpoint
/// in the resolved list. Applied after [`resolve_all`] so the resolve signatures (and their
/// many test call sites) stay credential-free.
pub fn apply_zebra_auth(servers: &mut [Server], auth: &ZebraAuth) {
    for server in servers {
        if server.kind == ServerKind::ZebraRpc {
            server.zebra_auth = auth.clone();
        }
    }
}

/// The `zebra` preset's local zebrad JSON-RPC ports (the default upstream). zebra ships with
/// RPC disabled - there is no upstream default port to inherit - and the zcashd-convention
/// RPC ports (8232/18232) are zecd's own, so the recommended `rpc.listen_addr` for a zebrad
/// serving zecd sits next to zebra's P2P ports (8233/18233) instead.
pub const ZEBRA_RPC_PORT_MAIN: u16 = 8234;
pub const ZEBRA_RPC_PORT_TEST: u16 = 18234;

// Presets as (host, port). TLS roots / force-mode are attached at resolve time.
const ECC_TESTNET: &[(&str, u16)] = &[("lightwalletd.testnet.electriccoin.co", 9067)];
const YWALLET_MAINNET: &[(&str, u16)] = &[
    ("lwd1.zcash-infra.com", 9067),
    ("lwd2.zcash-infra.com", 9067),
];
const ZEC_ROCKS_MAINNET: &[(&str, u16)] = &[("zec.rocks", 443)];
const ZEC_ROCKS_TESTNET: &[(&str, u16)] = &[("testnet.zec.rocks", 443)];

/// Resolve a single server token (`zebra` | `ecc` | `ywallet` | `zecrocks` |
/// `host:port[,host:port]` | `zebra://host:port`) for the given network into an ordered,
/// non-empty list of [`Server`]s.
/// Multi-endpoint presets and comma-separated host lists expand to all of their endpoints
/// (the first is the primary). A `host:port` may carry an `http://`/`https://` scheme to
/// force that endpoint's TLS mode, overriding the global `tls` setting (e.g. a plaintext
/// local node + TLS public fallbacks), or a `zebra://` scheme to mark it as a local zebrad
/// JSON-RPC endpoint instead of a lightwalletd.
pub fn resolve(
    server: &str,
    network: ZNetwork,
    roots: TlsRoots,
    force_tls: Option<bool>,
    proxy: Option<SocketAddr>,
) -> anyhow::Result<Vec<Server>> {
    // `zebra` (the default token) is a local zebrad's JSON-RPC on the recommended
    // `rpc.listen_addr` port for the network - shorthand for `zebra://127.0.0.1:8234`
    // (mainnet) / `zebra://127.0.0.1:18234` (testnet/regtest).
    if server == "zebra" {
        let port = match network {
            ZNetwork::Main => ZEBRA_RPC_PORT_MAIN,
            ZNetwork::Test | ZNetwork::Regtest(_) => ZEBRA_RPC_PORT_TEST,
        };
        return Ok(vec![Server::new(
            Cow::Borrowed("127.0.0.1"),
            port,
            ServerKind::ZebraRpc,
            network,
            roots,
            Some(false),
            proxy,
        )]);
    }

    // The named lightwalletd presets are public mainnet/testnet infrastructure; regtest has
    // none, so a regtest deployment must give an explicit `host:port` (handled by
    // `parse_host_list`).
    let preset: Option<&[(&str, u16)]> = match (server, network) {
        ("ecc", ZNetwork::Test) => Some(ECC_TESTNET),
        ("ecc", _) => None,
        ("ywallet", ZNetwork::Main) => Some(YWALLET_MAINNET),
        ("ywallet", _) => None,
        ("zecrocks", ZNetwork::Main) => Some(ZEC_ROCKS_MAINNET),
        ("zecrocks", ZNetwork::Test) => Some(ZEC_ROCKS_TESTNET),
        ("zecrocks", _) => None,
        _ => return parse_host_list(server, network, roots, force_tls, proxy),
    };

    match preset {
        // Preset consts are non-empty by construction, so the result is non-empty.
        Some(entries) => Ok(entries
            .iter()
            .map(|&(host, port)| {
                Server::new(
                    Cow::Borrowed(host),
                    port,
                    ServerKind::Lightwalletd,
                    network,
                    roots,
                    force_tls,
                    proxy,
                )
            })
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
    proxy: Option<SocketAddr>,
) -> anyhow::Result<Vec<Server>> {
    let mut out = Vec::new();
    for token in servers {
        out.extend(resolve(token, network, roots, force_tls, proxy)?);
    }
    if out.is_empty() {
        return Err(anyhow!("no lightwalletd servers configured"));
    }
    // RFC 7686: `.onion` names must never reach the DNS. Dialing one without a SOCKS proxy
    // would leak the hidden-service name to the local resolver (announcing which service the
    // operator intends to contact) and then fail anyway, so refuse at startup instead of
    // silently degrading the privacy property the operator configured the .onion for.
    if proxy.is_none() {
        if let Some(s) = out.iter().find(|s| s.host.ends_with(".onion")) {
            return Err(anyhow!(
                "lightwalletd endpoint {}:{} is a .onion address but connection = \"direct\"; \
                 set [lightwalletd] connection = \"tor\" (or \"socks5://<host>:<port>\")",
                s.host,
                s.port
            ));
        }
    }
    // The proxy invariant says no connection may silently bypass the configured SOCKS proxy,
    // and the zebra backend (plain HTTP to a local node) does not implement proxying - so the
    // combination is refused at startup rather than silently leaking direct connections.
    if proxy.is_some() {
        if let Some(s) = out.iter().find(|s| s.kind == ServerKind::ZebraRpc) {
            return Err(anyhow!(
                "zebra endpoint {}:{} cannot be combined with a SOCKS5 proxy; zebra:// \
                 endpoints are for local nodes - set [lightwalletd] connection = \"direct\" \
                 or remove the zebra endpoint",
                s.host,
                s.port
            ));
        }
    }
    Ok(out)
}

fn parse_host_list(
    s: &str,
    network: ZNetwork,
    roots: TlsRoots,
    force_tls: Option<bool>,
    proxy: Option<SocketAddr>,
) -> anyhow::Result<Vec<Server>> {
    let mut servers = Vec::new();
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        // An optional scheme sets the endpoint kind and TLS mode: `zebra://` marks a local
        // zebrad JSON-RPC endpoint (always plaintext HTTP); `http://`/`https://` set TLS per
        // lightwalletd endpoint, overriding the global `tls` setting - so a plaintext local
        // node and TLS public fallbacks can share one list.
        let (kind, force, rest) = if let Some(r) = entry.strip_prefix("zebra://") {
            (ServerKind::ZebraRpc, Some(false), r)
        } else if let Some(r) = entry.strip_prefix("https://") {
            (ServerKind::Lightwalletd, Some(true), r)
        } else if let Some(r) = entry.strip_prefix("http://") {
            (ServerKind::Lightwalletd, Some(false), r)
        } else {
            (ServerKind::Lightwalletd, force_tls, entry)
        };
        let (host, port_str) = rest
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("invalid server address '{entry}', expected host:port"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("invalid port in '{entry}'"))?;
        servers.push(Server::new(
            Cow::Owned(host.to_string()),
            port,
            kind,
            network,
            roots,
            force,
            proxy,
        ));
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
        let s = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None, None).unwrap();
        assert_eq!(s[0].host.as_ref(), "testnet.zec.rocks");
        assert!(s[0].use_tls());
        let s = resolve("zecrocks", ZNetwork::Main, TlsRoots::Native, None, None).unwrap();
        assert_eq!(s[0].host.as_ref(), "zec.rocks");
        // localhost auto -> plaintext
        let s = resolve(
            "127.0.0.1:9067",
            ZNetwork::Test,
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap();
        assert!(!s[0].use_tls());
        // forced plaintext for a co-located lightwalletd reached by service name
        let s = resolve(
            "lightwalletd:9067",
            ZNetwork::Test,
            TlsRoots::Native,
            Some(false),
            None,
        )
        .unwrap();
        assert!(!s[0].use_tls());
        // forced TLS even for localhost
        let s = resolve(
            "127.0.0.1:443",
            ZNetwork::Main,
            TlsRoots::Native,
            Some(true),
            None,
        )
        .unwrap();
        assert!(s[0].use_tls());
        assert!(resolve("ecc", ZNetwork::Main, TlsRoots::Native, None, None).is_err());
    }

    #[test]
    fn single_host_unchanged() {
        let s = resolve(
            "127.0.0.1:9067",
            ZNetwork::Test,
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.len(), 1);
        assert!(!s[0].use_tls());
    }

    #[test]
    fn resolves_multi_host() {
        let s = resolve(
            "a.example:9067,b.example:443",
            ZNetwork::Test,
            TlsRoots::Native,
            None,
            None,
        )
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
        let s = resolve("ywallet", ZNetwork::Main, TlsRoots::Native, None, None).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host.as_ref(), "lwd1.zcash-infra.com");
        assert_eq!(s[1].host.as_ref(), "lwd2.zcash-infra.com");
    }

    #[test]
    fn multi_host_tolerates_whitespace_and_trailing_comma() {
        let s = resolve("a:1 , b:2 ,", ZNetwork::Test, TlsRoots::Native, None, None).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host.as_ref(), "a");
        assert_eq!(s[1].host.as_ref(), "b");
    }

    #[test]
    fn empty_host_list_errors() {
        assert!(resolve(" , ", ZNetwork::Test, TlsRoots::Native, None, None).is_err());
        assert!(resolve(",", ZNetwork::Test, TlsRoots::Native, None, None).is_err());
    }

    #[test]
    fn scheme_prefix_sets_tls_per_server() {
        // Global tls=auto (None); scheme prefixes pick TLS per endpoint.
        let s = resolve(
            "http://lightwalletd:9067,https://zec.rocks:443",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
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
            None,
        )
        .unwrap();
        assert!(!s[0].use_tls()); // no scheme -> global force (plaintext)
        assert!(s[1].use_tls()); // scheme overrides to TLS
    }

    #[test]
    fn resolve_all_flattens() {
        let tokens = vec!["127.0.0.1:9067".to_string(), "zecrocks".to_string()];
        let s = resolve_all(&tokens, ZNetwork::Main, TlsRoots::Native, None, None).unwrap();
        assert_eq!(s.len(), 2); // 127.0.0.1:9067 + zec.rocks
        assert_eq!(s[0].host.as_ref(), "127.0.0.1");
        assert_eq!(s[1].host.as_ref(), "zec.rocks");
        assert!(resolve_all(&[], ZNetwork::Main, TlsRoots::Native, None, None).is_err());
    }

    #[test]
    fn tls_mode_parsing() {
        assert_eq!(parse_tls_mode("auto").unwrap(), None);
        assert_eq!(parse_tls_mode("no").unwrap(), Some(false));
        assert_eq!(parse_tls_mode("yes").unwrap(), Some(true));
        assert!(parse_tls_mode("maybe").is_err());
    }

    #[test]
    fn connection_mode_parsing() {
        // `direct` (and the empty string) means no proxy.
        assert_eq!(parse_connection_mode("direct").unwrap(), None);
        assert_eq!(parse_connection_mode("  ").unwrap(), None);
        // `tor` aliases Tor's default local SOCKS port.
        assert_eq!(
            parse_connection_mode("tor").unwrap(),
            Some("127.0.0.1:9050".parse().unwrap())
        );
        // Explicit SOCKS5 proxies are parsed verbatim, case-insensitively on the scheme.
        assert_eq!(
            parse_connection_mode("socks5://127.0.0.1:9150").unwrap(),
            Some("127.0.0.1:9150".parse().unwrap())
        );
        assert_eq!(
            parse_connection_mode("SOCKS5://192.168.1.5:1080").unwrap(),
            Some("192.168.1.5:1080".parse().unwrap())
        );
        // Garbage and unparseable proxy addresses are rejected.
        assert!(parse_connection_mode("proxy").is_err());
        assert!(parse_connection_mode("socks5://not-an-addr").is_err());
        assert!(parse_connection_mode("socks5://example.com:9050").is_err());
    }

    #[test]
    fn proxy_threads_through_resolve() {
        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let s = resolve(
            "zecrocks",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some(proxy),
        )
        .unwrap();
        assert_eq!(s[0].proxy, Some(proxy));
        // describe() surfaces the proxy so logs make the routing obvious.
        assert!(s[0].describe().contains("socks=127.0.0.1:9050"));
        // host:port lists carry the proxy onto every endpoint too.
        let s = resolve(
            "a.example:9067,b.example:443",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some(proxy),
        )
        .unwrap();
        assert!(s.iter().all(|srv| srv.proxy == Some(proxy)));
    }

    #[test]
    fn onion_host_skips_tls_by_default() {
        // `.onion` endpoints are encrypted by Tor; default heuristic must not require TLS.
        let s = resolve(
            "abcd1234.onion:9067",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some("127.0.0.1:9050".parse().unwrap()),
        )
        .unwrap();
        assert!(!s[0].use_tls());
        // …but an explicit `https://` still forces TLS over the onion route.
        let s = resolve(
            "https://abcd1234.onion:443",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap();
        assert!(s[0].use_tls());
    }

    /// A `.onion` endpoint without a SOCKS proxy must be refused at resolve time: the direct
    /// dial would leak the hidden-service name to the local DNS resolver (RFC 7686) and could
    /// never succeed anyway.
    #[test]
    fn onion_without_proxy_is_refused() {
        let err = resolve_all(
            &["abcd1234.onion:9067".to_string()],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(".onion"), "got: {err}");
        assert!(err.contains("connection"), "got: {err}");

        // The same endpoint with a proxy resolves fine.
        assert!(resolve_all(
            &["abcd1234.onion:9067".to_string()],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some("127.0.0.1:9050".parse().unwrap()),
        )
        .is_ok());

        // A .onion fallback hiding behind a clearnet primary is caught too.
        assert!(resolve_all(
            &[
                "zec.rocks:443".to_string(),
                "abcd1234.onion:9067".to_string()
            ],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn zebra_preset_resolves_to_local_zebrad_per_network() {
        // `zebra` (the built-in default) is a local zebrad on the recommended RPC port:
        // 8234 mainnet, 18234 testnet/regtest. Plaintext, kind ZebraRpc.
        for (network, port) in [
            (ZNetwork::Main, ZEBRA_RPC_PORT_MAIN),
            (ZNetwork::Test, ZEBRA_RPC_PORT_TEST),
            (crate::network::regtest(), ZEBRA_RPC_PORT_TEST),
        ] {
            let s = resolve("zebra", network, TlsRoots::Native, None, None).unwrap();
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].kind, ServerKind::ZebraRpc);
            assert_eq!(s[0].host.as_ref(), "127.0.0.1");
            assert_eq!(s[0].port, port);
            assert!(!s[0].use_tls());
        }
        // The preset must never clash with zecd's own default RPC ports (the wallet would
        // dial itself).
        assert_ne!(
            ZEBRA_RPC_PORT_MAIN,
            crate::config::ZECD_DEFAULTS.rpc_port_main
        );
        assert_ne!(
            ZEBRA_RPC_PORT_TEST,
            crate::config::ZECD_DEFAULTS.rpc_port_test
        );
        // Like any zebra endpoint, the preset refuses to combine with a SOCKS proxy.
        assert!(resolve_all(
            &["zebra".to_string()],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some("127.0.0.1:9050".parse().unwrap()),
        )
        .is_err());
    }

    #[test]
    fn zebra_scheme_parses_to_a_zebra_endpoint() {
        // `zebra://` marks a local zebrad JSON-RPC endpoint: plaintext, kind ZebraRpc.
        let s = resolve(
            "zebra://127.0.0.1:18232",
            crate::network::regtest(),
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].kind, ServerKind::ZebraRpc);
        assert_eq!(s[0].host.as_ref(), "127.0.0.1");
        assert_eq!(s[0].port, 18232);
        assert!(!s[0].use_tls());
        assert!(
            s[0].describe().starts_with("zebra-rpc 127.0.0.1:18232"),
            "{}",
            s[0].describe()
        );

        // Mixed list: a local zebra primary with a public lightwalletd fallback.
        let s = resolve(
            "zebra://127.0.0.1:8232,https://zec.rocks:443",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].kind, ServerKind::ZebraRpc);
        assert_eq!(s[1].kind, ServerKind::Lightwalletd);
        assert!(s[1].use_tls());

        // The usual host:port validation still applies behind the scheme.
        assert!(resolve(
            "zebra://nohost",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None
        )
        .is_err());
    }

    /// A `zebra://` endpoint with a SOCKS proxy configured must be refused at resolve time:
    /// the zebra backend dials direct plaintext HTTP, which would silently bypass the proxy
    /// the operator configured (the same invariant as the `.onion` refusal).
    #[test]
    fn zebra_with_proxy_is_refused() {
        let proxy: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        let err = resolve_all(
            &["zebra://127.0.0.1:8232".to_string()],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some(proxy),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("zebra"), "got: {err}");
        assert!(err.contains("SOCKS5"), "got: {err}");

        // A zebra endpoint hiding behind a clearnet lightwalletd primary is caught too.
        assert!(resolve_all(
            &[
                "zec.rocks:443".to_string(),
                "zebra://127.0.0.1:8232".to_string()
            ],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            Some(proxy),
        )
        .is_err());

        // Without a proxy the same list is fine.
        assert!(resolve_all(
            &[
                "zebra://127.0.0.1:8232".to_string(),
                "zec.rocks:443".to_string()
            ],
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None,
        )
        .is_ok());
    }

    #[test]
    fn zebra_auth_applies_only_to_zebra_endpoints() {
        let mut servers = resolve(
            "zebra://127.0.0.1:8232,zec.rocks:443",
            ZNetwork::Main,
            TlsRoots::Native,
            None,
            None,
        )
        .unwrap();
        let auth = crate::chain::zebra::ZebraAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };
        apply_zebra_auth(&mut servers, &auth);
        assert_eq!(servers[0].zebra_auth, auth);
        assert_eq!(
            servers[1].zebra_auth,
            crate::chain::zebra::ZebraAuth::default()
        );
    }

    // --- Network integration tests (hit the public zecrocks/ECC testnet lightwalletd) ---
    // Run with: cargo test -- --include-ignored

    use crate::chain::ChainSource as _;

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_get_latest_block() {
        let server = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut client = server
            .connect()
            .await
            .expect("connect to testnet.zec.rocks");
        let tip = client.latest_block().await.expect("latest_block");
        assert!(
            tip.height > 2_000_000,
            "unexpected testnet height {}",
            tip.height
        );
        assert_eq!(tip.hash.len(), 32, "block hash must be 32 bytes");
    }

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_lightd_info_and_treestate() {
        let server = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut client = server.connect().await.expect("connect");

        let info = client.server_info().await.expect("server_info");
        assert!(
            info.chain_name.contains("test"),
            "unexpected chain_name {}",
            info.chain_name
        );

        let tip = client.latest_block().await.expect("latest_block");
        let h = tip.height - 100;
        let ts = client
            .tree_state(zcash_protocol::consensus::BlockHeight::from_u32(h as u32))
            .await
            .expect("tree_state");
        assert_eq!(ts.height, h);
        ts.to_chain_state()
            .expect("tree state converts to chain state");
    }

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn failover_skips_dead_first_endpoint() {
        // A closed local port as the primary, with the live testnet endpoint as fallback.
        let servers = resolve(
            "127.0.0.1:1,testnet.zec.rocks:443",
            ZNetwork::Test,
            TlsRoots::Native,
            None,
            None,
        )
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
        let tip = client.latest_block().await.expect("latest_block");
        assert!(
            tip.height > 2_000_000,
            "unexpected testnet height {}",
            tip.height
        );
    }

    #[tokio::test]
    #[ignore = "hits zec.rocks (mainnet) over the network"]
    async fn mainnet_zecrocks_get_latest_block() {
        let server = resolve("zecrocks", ZNetwork::Main, TlsRoots::Native, None, None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let mut client = server.connect().await.expect("connect to zec.rocks");
        let tip = client.latest_block().await.expect("latest_block");
        assert!(
            tip.height > 2_500_000,
            "unexpected mainnet height {}",
            tip.height
        );
    }
}
