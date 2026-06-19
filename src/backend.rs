//! Upstream-endpoint management: resolving the configured `server` token into a single local
//! zebrad JSON-RPC endpoint and dialing it. zecd is zebra-only - the upstream is always a
//! local full node reached over plaintext HTTP JSON-RPC.

use std::borrow::Cow;
use std::time::Duration;

use anyhow::anyhow;

use crate::chain::zebra::{ZebraAuth, ZebraSource};
use crate::chain::AnySource;
use crate::network::ZNetwork;

/// The `zebra` preset's local zebrad JSON-RPC ports (the default upstream). zebra ships with
/// RPC disabled - there is no upstream default port to inherit - and the zcashd-convention
/// RPC ports (8232/18232) are zecd's own, so the recommended `rpc.listen_addr` for a zebrad
/// serving zecd sits next to zebra's P2P ports (8233/18233) instead.
pub const ZEBRA_RPC_PORT_MAIN: u16 = 8234;
pub const ZEBRA_RPC_PORT_TEST: u16 = 18234;

/// A resolved upstream endpoint: a local zebrad JSON-RPC server (plaintext HTTP).
#[derive(Clone, Debug)]
pub struct Server {
    host: Cow<'static, str>,
    port: u16,
    /// Needed by the zebra backend to parse raw blocks (consensus branch IDs).
    network: ZNetwork,
    /// zebrad RPC credentials (`[zebra]` config).
    zebra_auth: ZebraAuth,
}

impl Server {
    pub fn describe(&self) -> String {
        format!("zebra-rpc {}:{}", self.host, self.port)
    }

    /// Connect to this zebrad endpoint, bounding the whole dial with `timeout` so a
    /// hung/black-holed endpoint can't stall the caller. The dial is the client construction
    /// (cookie read) plus one `getblockchaininfo` round-trip.
    pub async fn connect_timeout(&self, timeout: Duration) -> anyhow::Result<AnySource> {
        let connect = ZebraSource::connect(&self.host, self.port, &self.zebra_auth, self.network);
        let source = tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| anyhow!("connect to {} timed out after {timeout:?}", self.describe()))??;
        Ok(AnySource::Zebra(source))
    }

    /// Connect with a default dial timeout. Convenience for tests; production callers use
    /// [`connect_timeout`](Server::connect_timeout).
    #[cfg(test)]
    pub async fn connect(&self) -> anyhow::Result<AnySource> {
        self.connect_timeout(Duration::from_secs(30)).await
    }
}

/// Attach zebrad RPC credentials (the `[zebra]` config section) to the resolved endpoint.
pub fn apply_zebra_auth(server: &mut Server, auth: &ZebraAuth) {
    server.zebra_auth = auth.clone();
}

/// Resolve the configured `server` token into a single local zebrad endpoint. Accepted forms:
/// `zebra` (the default - `127.0.0.1` on the recommended RPC port for the network), or an
/// explicit `zebra://host:port` / `host:port`.
pub fn resolve(server: &str, network: ZNetwork) -> anyhow::Result<Server> {
    if server == "zebra" {
        let port = match network {
            ZNetwork::Main => ZEBRA_RPC_PORT_MAIN,
            ZNetwork::Test | ZNetwork::Regtest(_) => ZEBRA_RPC_PORT_TEST,
        };
        return Ok(Server {
            host: Cow::Borrowed("127.0.0.1"),
            port,
            network,
            zebra_auth: ZebraAuth::default(),
        });
    }
    let rest = server.strip_prefix("zebra://").unwrap_or(server);
    let (host, port_str) = rest
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid zebra endpoint '{server}', expected zebra://host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid port in '{server}'"))?;
    if host.is_empty() {
        return Err(anyhow!(
            "invalid zebra endpoint '{server}', expected zebra://host:port"
        ));
    }
    Ok(Server {
        host: Cow::Owned(host.to_string()),
        port,
        network,
        zebra_auth: ZebraAuth::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zebra_preset_resolves_to_local_zebrad_per_network() {
        for (network, port) in [
            (ZNetwork::Main, ZEBRA_RPC_PORT_MAIN),
            (ZNetwork::Test, ZEBRA_RPC_PORT_TEST),
            (crate::network::regtest(), ZEBRA_RPC_PORT_TEST),
        ] {
            let s = resolve("zebra", network).unwrap();
            assert_eq!(s.host.as_ref(), "127.0.0.1");
            assert_eq!(s.port, port);
            assert!(s.describe().starts_with("zebra-rpc 127.0.0.1:"));
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
    }

    #[test]
    fn zebra_scheme_and_bare_host_parse() {
        let s = resolve("zebra://127.0.0.1:18232", crate::network::regtest()).unwrap();
        assert_eq!(s.host.as_ref(), "127.0.0.1");
        assert_eq!(s.port, 18232);
        // A bare host:port is accepted too (there is only one backend kind).
        let s = resolve("10.0.0.5:8234", ZNetwork::Main).unwrap();
        assert_eq!(s.host.as_ref(), "10.0.0.5");
        assert_eq!(s.port, 8234);
    }

    #[test]
    fn malformed_endpoints_error() {
        assert!(resolve("zebra://nohost", ZNetwork::Main).is_err());
        assert!(resolve("127.0.0.1:notaport", ZNetwork::Main).is_err());
        assert!(resolve("zebra://:8234", ZNetwork::Main).is_err());
    }

    #[test]
    fn apply_zebra_auth_sets_credentials() {
        let mut server = resolve("zebra://127.0.0.1:8232", ZNetwork::Main).unwrap();
        let auth = crate::chain::zebra::ZebraAuth {
            user: Some("u".into()),
            password: Some("p".into()),
            cookie: None,
        };
        apply_zebra_auth(&mut server, &auth);
        assert_eq!(server.zebra_auth, auth);
    }
}
