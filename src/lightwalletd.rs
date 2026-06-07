//! lightwalletd connection management. Ported from `zcash-devtool/src/remote.rs`, keeping
//! direct connections only. TLS is used for remote hosts and skipped for localhost, but can
//! be forced on/off explicitly (e.g. a co-located plaintext lightwalletd reached by service
//! name in docker-compose). No Tor/SOCKS.

use std::borrow::Cow;

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

    /// Open a gRPC connection to this lightwalletd server.
    pub async fn connect(&self) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
        let channel = Channel::from_shared(self.endpoint())?;
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
        Ok(CompactTxStreamerClient::new(channel.connect().await?))
    }
}

// Presets as (host, port). TLS roots / force-mode are attached at resolve time.
const ECC_TESTNET: &[(&str, u16)] = &[("lightwalletd.testnet.electriccoin.co", 9067)];
const YWALLET_MAINNET: &[(&str, u16)] =
    &[("lwd1.zcash-infra.com", 9067), ("lwd2.zcash-infra.com", 9067)];
const ZEC_ROCKS_MAINNET: &[(&str, u16)] = &[("zec.rocks", 443)];
const ZEC_ROCKS_TESTNET: &[(&str, u16)] = &[("testnet.zec.rocks", 443)];

/// Resolve a server string (`ecc` | `ywallet` | `zecrocks` | `host:port[,host:port]`) for the
/// given network into a concrete [`Server`].
pub fn resolve(
    server: &str,
    network: ZNetwork,
    roots: TlsRoots,
    force_tls: Option<bool>,
) -> anyhow::Result<Server> {
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

    match preset.and_then(|s| s.first()) {
        Some(&(host, port)) => Ok(Server::new(Cow::Borrowed(host), port, roots, force_tls)),
        None => Err(anyhow!(
            "lightwalletd preset '{server}' does not serve {}",
            network.name()
        )),
    }
}

fn parse_host_list(s: &str, roots: TlsRoots, force_tls: Option<bool>) -> anyhow::Result<Server> {
    let first = s.split(',').next().unwrap_or(s);
    let (host, port_str) = first
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid lightwalletd address '{first}', expected host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid port in '{first}'"))?;
    Ok(Server::new(Cow::Owned(host.to_string()), port, roots, force_tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_presets_and_custom() {
        let s = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None).unwrap();
        assert_eq!(s.host.as_ref(), "testnet.zec.rocks");
        assert!(s.use_tls());
        let s = resolve("zecrocks", ZNetwork::Main, TlsRoots::Native, None).unwrap();
        assert_eq!(s.host.as_ref(), "zec.rocks");
        // localhost auto -> plaintext
        let s = resolve("127.0.0.1:9067", ZNetwork::Test, TlsRoots::Native, None).unwrap();
        assert!(!s.use_tls());
        // forced plaintext for a co-located lightwalletd reached by service name
        let s = resolve("lightwalletd:9067", ZNetwork::Test, TlsRoots::Native, Some(false)).unwrap();
        assert!(!s.use_tls());
        // forced TLS even for localhost
        let s = resolve("127.0.0.1:443", ZNetwork::Main, TlsRoots::Native, Some(true)).unwrap();
        assert!(s.use_tls());
        assert!(resolve("ecc", ZNetwork::Main, TlsRoots::Native, None).is_err());
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
        let server = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None).unwrap();
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
        let server = resolve("zecrocks", ZNetwork::Test, TlsRoots::Native, None).unwrap();
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
    #[ignore = "hits zec.rocks (mainnet) over the network"]
    async fn mainnet_zecrocks_get_latest_block() {
        use zcash_client_backend::proto::service;
        let server = resolve("zecrocks", ZNetwork::Main, TlsRoots::Native, None).unwrap();
        let mut client = server.connect().await.expect("connect to zec.rocks");
        let tip = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .expect("get_latest_block")
            .into_inner();
        assert!(tip.height > 2_500_000, "unexpected mainnet height {}", tip.height);
    }
}
