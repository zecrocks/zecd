//! Upstream-endpoint management: resolving the configured `server` token into a single
//! endpoint - a local zebrad JSON-RPC server ("full mode") or a lightwalletd gRPC server
//! ("light mode") - and dialing it.
//!
//! Token grammar (`[backend] server` / `--server`) - every form names an explicit host, and
//! there are no shorthand aliases for particular servers:
//!  * `zebra://host:port` - a zebrad JSON-RPC endpoint (plaintext HTTP, local-only by policy -
//!    see the cleartext gate in `chain::zebra`). This is the default upstream's form:
//!    `zebra://127.0.0.1:8234` on mainnet / `zebra://127.0.0.1:18234` on test/regtest (see
//!    `config::default_server`).
//!  * `https://host[:port]` - a lightwalletd endpoint, TLS forced on.
//!  * `http://host:port` - a lightwalletd endpoint, TLS forced off (the regtest harness's
//!    local plaintext lightwalletd; refused toward public hosts unless
//!    `allow_remote_cleartext`).
//!  * bare `host:port` - a lightwalletd endpoint; TLS decided by the locality heuristic
//!    (loopback/private-network plaintext, public TLS), overridable via `[backend] tls`.

use std::borrow::Cow;
use std::time::Duration;

use anyhow::anyhow;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::chain::lwd::LwdSource;
use crate::chain::zebra::{host_is_local, CleartextPolicy, ZebraAuth, ZebraSource};
use crate::chain::AnySource;
use crate::network::ZNetwork;

/// The local zebrad JSON-RPC ports the default upstream points at (see
/// `config::default_server`). zebra ships with RPC disabled - there is no upstream default port
/// to inherit - and the zcashd-convention RPC ports (8232/18232) are zecd's own, so the
/// recommended `rpc.listen_addr` for a zebrad serving zecd sits next to zebra's P2P ports
/// (8233/18233) instead.
pub const ZEBRA_RPC_PORT_MAIN: u16 = 8234;
pub const ZEBRA_RPC_PORT_TEST: u16 = 18234;

/// Which set of root certificates to trust for lightwalletd TLS connections.
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

/// Parse a `[backend] tls` setting into a force-TLS override: `auto` (None) uses the locality
/// heuristic; `yes`/`no` force it. lightwalletd endpoints only - `zebra://` is always
/// plaintext HTTP.
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

/// What protocol a resolved endpoint speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerKind {
    /// A lightwalletd `CompactTxStreamer` gRPC endpoint ("light mode").
    Lightwalletd,
    /// A local zebrad JSON-RPC endpoint (`zebra://host:port`), plaintext HTTP.
    ZebraRpc,
}

/// A resolved upstream endpoint (local zebrad or lightwalletd).
#[derive(Clone, Debug)]
pub struct Server {
    host: Cow<'static, str>,
    port: u16,
    kind: ServerKind,
    /// Needed by the zebra backend to parse raw blocks (consensus branch IDs).
    network: ZNetwork,
    /// Root store for lightwalletd TLS (`[backend] tls_roots`).
    roots: TlsRoots,
    /// `Some(true/false)` forces TLS on/off; `None` uses the locality heuristic.
    /// lightwalletd only; `zebra://` endpoints are always plaintext HTTP.
    force_tls: Option<bool>,
    /// zebrad RPC credentials (`[zebra]` config); never applied to lightwalletd endpoints
    /// (lightwalletd has no client auth - the credentials must not ride to a foreign host).
    zebra_auth: ZebraAuth,
    /// Locality policy (`[backend] rfc1918_is_local` / `allow_remote_cleartext`). Gates
    /// credentialed plaintext to zebra, and *any* plaintext to a lightwalletd (query privacy).
    cleartext_policy: CleartextPolicy,
}

impl Server {
    fn new(host: Cow<'static, str>, port: u16, kind: ServerKind, network: ZNetwork) -> Self {
        Server {
            host,
            port,
            kind,
            network,
            roots: TlsRoots::default(),
            force_tls: None,
            zebra_auth: ZebraAuth::default(),
            cleartext_policy: CleartextPolicy::default(),
        }
    }

    pub fn kind(&self) -> ServerKind {
        self.kind
    }

    /// Whether the lightwalletd dial uses TLS: the forced setting when present, else the
    /// locality heuristic - loopback/private-network hosts (docker/k8s/LAN, where a public
    /// CA-signed cert is impossible) dial plaintext, everything else TLS.
    fn use_tls(&self) -> bool {
        self.force_tls
            .unwrap_or_else(|| !host_is_local(&self.host, true))
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
        match self.kind {
            ServerKind::Lightwalletd => {
                format!(
                    "lightwalletd {}:{} (tls={})",
                    self.host,
                    self.port,
                    self.use_tls()
                )
            }
            ServerKind::ZebraRpc => format!("zebra-rpc {}:{}", self.host, self.port),
        }
    }

    /// Connect to this endpoint, bounding the whole dial with `timeout` so a hung/black-holed
    /// endpoint can't stall the caller. For lightwalletd that is the TCP/TLS connect plus the
    /// `GetLightdInfo` capability probe; for a zebra endpoint it is the client construction
    /// (cookie read) plus one `getblockchaininfo` round-trip - each backend's closest analog
    /// of a dial.
    pub async fn connect_timeout(&self, timeout: Duration) -> anyhow::Result<AnySource> {
        match self.kind {
            ServerKind::Lightwalletd => {
                let source = tokio::time::timeout(timeout, self.connect_lwd())
                    .await
                    .map_err(|_| {
                        anyhow!("connect to {} timed out after {timeout:?}", self.describe())
                    })??;
                Ok(AnySource::Lwd(source))
            }
            ServerKind::ZebraRpc => {
                let connect = ZebraSource::connect(
                    &self.host,
                    self.port,
                    &self.zebra_auth,
                    self.network,
                    self.cleartext_policy,
                );
                let source = tokio::time::timeout(timeout, connect).await.map_err(|_| {
                    anyhow!("connect to {} timed out after {timeout:?}", self.describe())
                })??;
                Ok(AnySource::Zebra(source))
            }
        }
    }

    /// Dial this lightwalletd server (TCP/TLS connect + capability probe).
    async fn connect_lwd(&self) -> anyhow::Result<LwdSource> {
        if !self.use_tls() {
            // Plaintext gate, the lightwalletd analog of the zebra cleartext-credential gate.
            // There are no credentials here; what plaintext leaks is *query privacy* (which
            // addresses/txids this wallet cares about) to every on-path observer. A
            // loopback/private-network hop (the regtest harness, a LAN lightwalletd) is fine;
            // a globally-routable plaintext hop is refused unless the operator explicitly
            // opted in for an out-of-band-secured link.
            if !host_is_local(&self.host, self.cleartext_policy.rfc1918_is_local)
                && !self.cleartext_policy.allow_remote_cleartext
            {
                return Err(anyhow!(
                    "refusing plaintext lightwalletd connection to non-local host {}:{} - \
                     use https:// (or tls = \"yes\"), or set [backend] \
                     allow_remote_cleartext = true if this hop is secured out-of-band",
                    self.host,
                    self.port
                ));
            }
            tracing::info!(
                "connecting to lightwalletd {}:{} without TLS; set [backend] tls = \"yes\" \
                 to require TLS",
                self.host,
                self.port
            );
        }
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
        let channel = endpoint.connect().await?;
        LwdSource::connect(channel).await
    }

    /// Connect with a default dial timeout. Convenience for tests; production callers use
    /// [`connect_timeout`](Server::connect_timeout).
    #[cfg(test)]
    pub async fn connect(&self) -> anyhow::Result<AnySource> {
        self.connect_timeout(Duration::from_secs(30)).await
    }
}

/// Attach zebrad RPC credentials (the `[zebra]` config section) to the resolved endpoint.
/// A no-op for a lightwalletd endpoint: lightwalletd has no client auth, and the zebra
/// credentials must never ride to a foreign host.
pub fn apply_zebra_auth(server: &mut Server, auth: &ZebraAuth) {
    if server.kind == ServerKind::ZebraRpc {
        server.zebra_auth = auth.clone();
    }
}

/// Set the locality/cleartext policy on the resolved endpoint (`[backend] rfc1918_is_local` /
/// `allow_remote_cleartext`). For zebra it gates credentials over the plaintext connection;
/// for lightwalletd it gates plaintext (query privacy) toward non-local hosts.
pub fn apply_cleartext_policy(server: &mut Server, policy: CleartextPolicy) {
    server.cleartext_policy = policy;
}

/// Set the lightwalletd TLS options (`[backend] tls` / `tls_roots`) on the resolved endpoint.
/// The scheme prefix wins over the global `tls` setting (an explicit `https://`/`http://`
/// already forced it at resolve time).
pub fn apply_tls(server: &mut Server, force_tls: Option<bool>, roots: TlsRoots) {
    server.roots = roots;
    if server.force_tls.is_none() {
        server.force_tls = force_tls;
    }
}

/// The error for a `server` token that names no host:port. Endpoint aliases (`zebra`,
/// `zecrocks`) were removed in favour of always spelling the endpoint out, so the two former
/// presets get a migration hint pointing at the form that replaces them.
fn invalid_endpoint(server: &str) -> anyhow::Error {
    let hint = match server {
        "zebra" => {
            "; the 'zebra' alias was removed - write the endpoint out, e.g. \
             zebra://127.0.0.1:8234 (mainnet) or zebra://127.0.0.1:18234 (test/regtest)"
        }
        "zecrocks" => {
            "; the 'zecrocks' alias was removed - write the endpoint out, e.g. \
             https://zec.rocks:443 (mainnet) or https://testnet.zec.rocks:443 (testnet)"
        }
        _ => "",
    };
    anyhow!(
        "invalid endpoint '{server}', expected host:port (or zebra://host:port | \
         https://host[:port] | http://host:port){hint}"
    )
}

/// Resolve the configured `server` token into a single upstream endpoint. See the module doc
/// for the accepted grammar.
pub fn resolve(server: &str, network: ZNetwork) -> anyhow::Result<Server> {
    let (kind, force_tls, rest) = if let Some(rest) = server.strip_prefix("zebra://") {
        (ServerKind::ZebraRpc, None, rest)
    } else if let Some(rest) = server.strip_prefix("https://") {
        (ServerKind::Lightwalletd, Some(true), rest)
    } else if let Some(rest) = server.strip_prefix("http://") {
        (ServerKind::Lightwalletd, Some(false), rest)
    } else {
        // A bare host:port is a lightwalletd endpoint; TLS by the locality heuristic.
        (ServerKind::Lightwalletd, None, server)
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port_str)) => {
            let port: u16 = port_str
                .parse()
                .map_err(|_| anyhow!("invalid port in '{server}'"))?;
            (host, port)
        }
        // `https://host` without a port defaults to 443 (the public-lightwalletd norm);
        // every other form requires an explicit port.
        None if force_tls == Some(true) => (rest, 443),
        None => return Err(invalid_endpoint(server)),
    };
    if host.is_empty() {
        return Err(anyhow!("invalid endpoint '{server}': empty host"));
    }
    let mut s = Server::new(Cow::Owned(host.to_string()), port, kind, network);
    s.force_tls = force_tls;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_server_resolves_to_local_zebrad_per_network() {
        // The built-in default is an ordinary explicit token, so it goes through the same
        // grammar as anything a user writes - and this pins it to the documented ports.
        for (network, port) in [
            (ZNetwork::Main, ZEBRA_RPC_PORT_MAIN),
            (ZNetwork::Test, ZEBRA_RPC_PORT_TEST),
            (crate::network::regtest(), ZEBRA_RPC_PORT_TEST),
        ] {
            let token = crate::config::default_server(network);
            let s = resolve(token, network).unwrap();
            assert_eq!(s.host.as_ref(), "127.0.0.1");
            assert_eq!(s.port, port, "{token} should resolve to port {port}");
            assert_eq!(s.kind, ServerKind::ZebraRpc);
            assert!(s.describe().starts_with("zebra-rpc 127.0.0.1:"));
        }
        // The default must never clash with zecd's own RPC ports (the wallet would dial
        // itself).
        assert_ne!(
            ZEBRA_RPC_PORT_MAIN,
            crate::config::ZECD_DEFAULTS.rpc_port_main
        );
        assert_ne!(
            ZEBRA_RPC_PORT_TEST,
            crate::config::ZECD_DEFAULTS.rpc_port_test
        );
    }

    #[test]
    fn removed_endpoint_aliases_are_rejected_with_a_migration_hint() {
        // Endpoints are always spelled out; the former `zebra` / `zecrocks` presets are not
        // silently reinterpreted as bare hostnames - they are a hard error naming the form
        // that replaces them.
        for (alias, replacement) in [
            ("zebra", "zebra://127.0.0.1:8234"),
            ("zecrocks", "https://zec.rocks:443"),
        ] {
            for network in [ZNetwork::Main, ZNetwork::Test, crate::network::regtest()] {
                let err = match resolve(alias, network) {
                    Ok(s) => panic!("'{alias}' must not resolve, got {}", s.describe()),
                    Err(e) => e.to_string(),
                };
                assert!(
                    err.contains("was removed") && err.contains(replacement),
                    "{alias} error should point at {replacement}, got: {err}"
                );
            }
        }
    }

    #[test]
    fn zebra_scheme_and_lightwalletd_forms_parse() {
        let s = resolve("zebra://127.0.0.1:18232", crate::network::regtest()).unwrap();
        assert_eq!(s.host.as_ref(), "127.0.0.1");
        assert_eq!(s.port, 18232);
        assert_eq!(s.kind, ServerKind::ZebraRpc);

        // A bare host:port is a lightwalletd endpoint (light mode).
        let s = resolve("lwd.example.com:9067", ZNetwork::Main).unwrap();
        assert_eq!(s.kind, ServerKind::Lightwalletd);
        assert_eq!(s.port, 9067);
        assert!(s.use_tls(), "public host defaults to TLS");

        // Scheme prefixes force the TLS mode per endpoint.
        let s = resolve("https://zec.rocks", ZNetwork::Main).unwrap();
        assert_eq!(s.kind, ServerKind::Lightwalletd);
        assert_eq!(s.port, 443, "https defaults to 443");
        assert!(s.use_tls());

        let s = resolve("http://127.0.0.1:9067", crate::network::regtest()).unwrap();
        assert_eq!(s.kind, ServerKind::Lightwalletd);
        assert!(!s.use_tls(), "http:// forces plaintext");
    }

    #[test]
    fn tls_locality_heuristic_and_overrides() {
        // Loopback and private-network hosts dial plaintext by default…
        for host in [
            "127.0.0.1:9067",
            "localhost:9067",
            "10.0.0.5:9067",
            "192.168.1.2:9067",
        ] {
            let s = resolve(host, ZNetwork::Main).unwrap();
            assert!(!s.use_tls(), "{host} should default to plaintext");
        }
        // …public hosts dial TLS.
        for host in ["zec.rocks:443", "203.0.113.5:9067"] {
            let s = resolve(host, ZNetwork::Main).unwrap();
            assert!(s.use_tls(), "{host} should default to TLS");
        }
        // The global `tls` setting overrides the heuristic, but not a scheme prefix.
        let mut s = resolve("127.0.0.1:9067", ZNetwork::Main).unwrap();
        apply_tls(&mut s, Some(true), TlsRoots::default());
        assert!(s.use_tls(), "tls = \"yes\" forces TLS on a local host");
        let mut s = resolve("http://203.0.113.5:9067", ZNetwork::Main).unwrap();
        apply_tls(&mut s, Some(true), TlsRoots::default());
        assert!(
            !s.use_tls(),
            "an explicit http:// scheme wins over the global tls setting"
        );
    }

    #[test]
    fn tls_mode_and_roots_parsing() {
        assert_eq!(parse_tls_mode("auto").unwrap(), None);
        assert_eq!(parse_tls_mode("yes").unwrap(), Some(true));
        assert_eq!(parse_tls_mode("no").unwrap(), Some(false));
        assert!(parse_tls_mode("maybe").is_err());
        assert_eq!(TlsRoots::parse("native").unwrap(), TlsRoots::Native);
        assert_eq!(TlsRoots::parse("system").unwrap(), TlsRoots::Native);
        assert_eq!(TlsRoots::parse("webpki").unwrap(), TlsRoots::Webpki);
        assert_eq!(TlsRoots::parse("mozilla").unwrap(), TlsRoots::Webpki);
        assert!(TlsRoots::parse("other").is_err());
    }

    #[test]
    fn malformed_endpoints_error() {
        assert!(resolve("zebra://nohost", ZNetwork::Main).is_err());
        assert!(resolve("127.0.0.1:notaport", ZNetwork::Main).is_err());
        assert!(resolve("zebra://:8234", ZNetwork::Main).is_err());
        assert!(resolve("http://nohost", ZNetwork::Main).is_err());
        assert!(resolve("https://:443", ZNetwork::Main).is_err());
    }

    #[test]
    fn apply_zebra_auth_sets_credentials_on_zebra_only() {
        let auth = crate::chain::zebra::ZebraAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };
        let mut server = resolve("zebra://127.0.0.1:8232", ZNetwork::Main).unwrap();
        apply_zebra_auth(&mut server, &auth);
        assert_eq!(server.zebra_auth, auth);

        // The zebra credentials must never ride to a lightwalletd endpoint.
        let mut lwd = resolve("zec.rocks:443", ZNetwork::Main).unwrap();
        apply_zebra_auth(&mut lwd, &auth);
        assert_eq!(lwd.zebra_auth, ZebraAuth::default());
    }

    /// The plaintext-lightwalletd gate: plaintext to a non-local host is refused before any
    /// dial (query privacy), while loopback plaintext (the regtest harness) and the
    /// `allow_remote_cleartext` override pass the gate.
    #[tokio::test]
    async fn plaintext_lightwalletd_to_public_host_is_refused() {
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): globally-routable but guaranteed unrouted,
        // so if the gate didn't fire this would hang until the timeout instead of erroring.
        let server = resolve("http://203.0.113.5:9067", ZNetwork::Main).unwrap();
        let err = match server.connect_timeout(Duration::from_secs(5)).await {
            Ok(_) => panic!("plaintext lightwalletd to a public host must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("plaintext"), "gate error expected, got: {err}");
        assert!(
            err.contains("allow_remote_cleartext"),
            "message should name the override: {err}"
        );

        // The override lets the same endpoint past the gate (it then fails on the dial, not
        // the gate) - asserting the policy is threaded, not hard-coded.
        let mut allowed = resolve("http://203.0.113.5:9067", ZNetwork::Main).unwrap();
        apply_cleartext_policy(
            &mut allowed,
            CleartextPolicy {
                rfc1918_is_local: true,
                allow_remote_cleartext: true,
            },
        );
        let err = match allowed.connect_timeout(Duration::from_millis(200)).await {
            Ok(_) => panic!("unrouted host cannot actually complete the dial"),
            Err(e) => e.to_string(),
        };
        assert!(
            !err.contains("plaintext lightwalletd"),
            "override must bypass the gate, got: {err}"
        );
    }

    /// End-to-end wiring: the cleartext-credential gate runs inside `ZebraClient::new`, which
    /// `connect_timeout` reaches *before* any network I/O, so a credentialed globally-routable
    /// endpoint under the default policy is refused without dialing. Proves the whole chain
    /// (`resolve` → `apply_zebra_auth` → `apply_cleartext_policy` → `connect_timeout`) honors the
    /// policy - the unit tests bypass it by calling `ZebraClient::new` directly.
    #[tokio::test]
    async fn connect_refuses_credentialed_public_host_without_dialing() {
        let creds = crate::chain::zebra::ZebraAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };

        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737) - globally-routable but guaranteed unrouted, so
        // if the gate *didn't* fire this would hang until the dial timeout rather than pass.
        let mut server = resolve("zebra://203.0.113.5:8234", ZNetwork::Main).unwrap();
        apply_zebra_auth(&mut server, &creds);
        apply_cleartext_policy(&mut server, CleartextPolicy::default());
        let err = match server.connect_timeout(Duration::from_secs(5)).await {
            Ok(_) => panic!("credentialed public host must be refused by the gate"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("cleartext"), "gate error expected, got: {err}");
        assert!(
            err.contains("allow_remote_cleartext"),
            "message should name the override: {err}"
        );

        // The override lets the same endpoint past the gate (it then fails on the dial, not the
        // gate) - asserting the policy is actually threaded, not hard-coded.
        let mut allowed = resolve("zebra://203.0.113.5:8234", ZNetwork::Main).unwrap();
        apply_zebra_auth(&mut allowed, &creds);
        apply_cleartext_policy(
            &mut allowed,
            CleartextPolicy {
                rfc1918_is_local: true,
                allow_remote_cleartext: true,
            },
        );
        let err = match allowed.connect_timeout(Duration::from_millis(200)).await {
            Ok(_) => panic!("unrouted host cannot actually complete the dial"),
            Err(e) => e.to_string(),
        };
        assert!(
            !err.contains("cleartext"),
            "override must bypass the gate, got: {err}"
        );
    }

    // ---- Network integration tests (run with `cargo test -- --include-ignored`) ----

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_get_latest_block() {
        use crate::chain::ChainSource as _;
        let server = resolve("https://testnet.zec.rocks:443", ZNetwork::Test).unwrap();
        let mut source = server
            .connect()
            .await
            .expect("connect to testnet.zec.rocks");
        let tip = source.latest_block().await.expect("latest block");
        assert!(tip.height > 2_000_000, "testnet is past height 2M");
        assert_eq!(tip.hash.len(), 32);
    }

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_lightd_info_and_treestate() {
        use crate::chain::ChainSource as _;
        let server = resolve("https://testnet.zec.rocks:443", ZNetwork::Test).unwrap();
        let mut source = server
            .connect()
            .await
            .expect("connect to testnet.zec.rocks");
        let info = source.server_info().await.expect("lightd info");
        assert!(
            info.chain_name.contains("test"),
            "expected a testnet server, got chain {:?}",
            info.chain_name
        );
        let tip = source.latest_block().await.expect("latest block");
        let h = zcash_protocol::consensus::BlockHeight::from_u32(tip.height as u32 - 100);
        let ts = source.tree_state(h).await.expect("tree state");
        assert_eq!(ts.height, u64::from(h), "tree state echoes the height");
        ts.to_chain_state()
            .expect("tree state converts to a ChainState");
    }

    #[tokio::test]
    #[ignore = "hits zec.rocks (mainnet) over the network"]
    async fn mainnet_zecrocks_get_latest_block() {
        use crate::chain::ChainSource as _;
        let server = resolve("https://zec.rocks:443", ZNetwork::Main).unwrap();
        let mut source = server.connect().await.expect("connect to zec.rocks");
        let tip = source.latest_block().await.expect("latest block");
        assert!(tip.height > 2_500_000, "mainnet is past height 2.5M");
        assert_eq!(tip.hash.len(), 32);
    }
}
