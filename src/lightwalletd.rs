//! lightwalletd connection management. Ported from `zcash-devtool/src/remote.rs`, keeping
//! direct connections only (TLS for remote hosts, plaintext for localhost). The deployment
//! model is either a local self-hosted lightwalletd or the public zecrocks infrastructure,
//! both reached directly - no Tor/SOCKS.

use std::borrow::Cow;

use anyhow::anyhow;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_protocol::consensus::Network;

/// Which set of root certificates to trust for TLS connections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsRoots {
    /// The OS trust store (honors `SSL_CERT_FILE`). Works behind TLS-intercepting proxies and
    /// with local/corporate CAs. Default.
    Native,
    /// The embedded Mozilla root bundle (webpki-roots). Good for minimal containers with no
    /// system trust store, but won't trust private/proxy CAs.
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

impl Default for TlsRoots {
    fn default() -> Self {
        TlsRoots::Native
    }
}

/// A resolved lightwalletd endpoint.
#[derive(Clone, Debug)]
pub struct Server {
    host: Cow<'static, str>,
    port: u16,
    tls: TlsRoots,
}

impl Server {
    fn new(host: Cow<'static, str>, port: u16, tls: TlsRoots) -> Self {
        Server { host, port, tls }
    }

    /// localhost is plaintext; everything else uses TLS.
    fn use_tls(&self) -> bool {
        !matches!(self.host.as_ref(), "localhost" | "127.0.0.1" | "::1")
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
        format!("{}:{}", self.host, self.port)
    }

    /// Open a gRPC connection to this lightwalletd server.
    pub async fn connect(&self) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
        let channel = Channel::from_shared(self.endpoint())?;
        let channel = if self.use_tls() {
            let tls = ClientTlsConfig::new()
                .domain_name(self.host.to_string())
                .assume_http2(true);
            let tls = match self.tls {
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

// Presets as (host, port). TLS roots are attached at resolve time.
const ECC_TESTNET: &[(&str, u16)] = &[("lightwalletd.testnet.electriccoin.co", 9067)];
const YWALLET_MAINNET: &[(&str, u16)] =
    &[("lwd1.zcash-infra.com", 9067), ("lwd2.zcash-infra.com", 9067)];
const ZEC_ROCKS_MAINNET: &[(&str, u16)] = &[("zec.rocks", 443)];
const ZEC_ROCKS_TESTNET: &[(&str, u16)] = &[("testnet.zec.rocks", 443)];

/// Resolve a server string (`ecc` | `ywallet` | `zecrocks` | `host:port[,host:port]`) for the
/// given network into a concrete [`Server`].
pub fn resolve(server: &str, network: Network, tls: TlsRoots) -> anyhow::Result<Server> {
    let preset: Option<&[(&str, u16)]> = match (server, network) {
        ("ecc", Network::TestNetwork) => Some(ECC_TESTNET),
        ("ecc", Network::MainNetwork) => None,
        ("ywallet", Network::MainNetwork) => Some(YWALLET_MAINNET),
        ("ywallet", Network::TestNetwork) => None,
        ("zecrocks", Network::MainNetwork) => Some(ZEC_ROCKS_MAINNET),
        ("zecrocks", Network::TestNetwork) => Some(ZEC_ROCKS_TESTNET),
        _ => return parse_host_list(server, tls),
    };

    match preset.and_then(|s| s.first()) {
        Some(&(host, port)) => Ok(Server::new(Cow::Borrowed(host), port, tls)),
        None => Err(anyhow!(
            "lightwalletd preset '{server}' does not serve {network:?}"
        )),
    }
}

fn parse_host_list(s: &str, tls: TlsRoots) -> anyhow::Result<Server> {
    let first = s.split(',').next().unwrap_or(s);
    let (host, port_str) = first
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid lightwalletd address '{first}', expected host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid port in '{first}'"))?;
    Ok(Server::new(Cow::Owned(host.to_string()), port, tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_presets_and_custom() {
        let s = resolve("zecrocks", Network::TestNetwork, TlsRoots::Native).unwrap();
        assert_eq!(s.describe(), "testnet.zec.rocks:443");
        let s = resolve("zecrocks", Network::MainNetwork, TlsRoots::Native).unwrap();
        assert_eq!(s.describe(), "zec.rocks:443");
        let s = resolve("127.0.0.1:9067", Network::TestNetwork, TlsRoots::Native).unwrap();
        assert_eq!(s.describe(), "127.0.0.1:9067");
        assert!(!s.use_tls());
        assert!(resolve("ecc", Network::MainNetwork, TlsRoots::Native).is_err());
    }

    // --- Network integration tests (hit the public zecrocks/ECC testnet lightwalletd) ---
    // Ignored by default so offline `cargo test` stays green; run with:
    //   cargo test -- --include-ignored

    #[tokio::test]
    #[ignore = "hits testnet.zec.rocks over the network"]
    async fn testnet_zecrocks_get_latest_block() {
        use zcash_client_backend::proto::service;
        let server = resolve("zecrocks", Network::TestNetwork, TlsRoots::Native).unwrap();
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
        let server = resolve("zecrocks", Network::TestNetwork, TlsRoots::Native).unwrap();
        let mut client = server.connect().await.expect("connect");

        let info = client
            .get_lightd_info(service::Empty {})
            .await
            .expect("get_lightd_info")
            .into_inner();
        assert!(!info.vendor.is_empty());
        assert!(info.block_height > 2_000_000);
        // Testnet consensus chain name.
        assert!(
            info.chain_name.contains("test"),
            "unexpected chain_name {}",
            info.chain_name
        );

        // A tree state for a recent block must be retrievable and convertible.
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
        let server = resolve("zecrocks", Network::MainNetwork, TlsRoots::Native).unwrap();
        let mut client = server.connect().await.expect("connect to zec.rocks");
        let tip = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .expect("get_latest_block")
            .into_inner();
        assert!(tip.height > 2_500_000, "unexpected mainnet height {}", tip.height);
    }
}
