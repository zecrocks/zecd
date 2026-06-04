//! lightwalletd connection management. Ported from `zcash-devtool/src/remote.rs`, keeping
//! direct connections only (TLS for remote hosts, plaintext for localhost). The deployment
//! model is either a local self-hosted lightwalletd or the public zecrocks infrastructure,
//! both reached directly - no Tor/SOCKS.

use std::borrow::Cow;

use anyhow::anyhow;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_protocol::consensus::Network;

/// A resolved lightwalletd endpoint.
#[derive(Clone, Debug)]
pub struct Server {
    host: Cow<'static, str>,
    port: u16,
}

impl Server {
    const fn fixed(host: &'static str, port: u16) -> Self {
        Server { host: Cow::Borrowed(host), port }
    }

    fn custom(host: String, port: u16) -> Self {
        Server { host: Cow::Owned(host), port }
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
                .assume_http2(true)
                .with_webpki_roots();
            channel.tls_config(tls)?
        } else {
            channel
        };
        Ok(CompactTxStreamerClient::new(channel.connect().await?))
    }
}

const ECC_TESTNET: &[Server] = &[Server::fixed("lightwalletd.testnet.electriccoin.co", 9067)];
const YWALLET_MAINNET: &[Server] = &[
    Server::fixed("lwd1.zcash-infra.com", 9067),
    Server::fixed("lwd2.zcash-infra.com", 9067),
];
const ZEC_ROCKS_MAINNET: &[Server] = &[Server::fixed("zec.rocks", 443)];
const ZEC_ROCKS_TESTNET: &[Server] = &[Server::fixed("testnet.zec.rocks", 443)];

/// Resolve a server string (`ecc` | `ywallet` | `zecrocks` | `host:port[,host:port]`) for the
/// given network into a concrete [`Server`].
pub fn resolve(server: &str, network: Network) -> anyhow::Result<Server> {
    let preset = match (server, network) {
        ("ecc", Network::TestNetwork) => Some(ECC_TESTNET),
        ("ecc", Network::MainNetwork) => None,
        ("ywallet", Network::MainNetwork) => Some(YWALLET_MAINNET),
        ("ywallet", Network::TestNetwork) => None,
        ("zecrocks", Network::MainNetwork) => Some(ZEC_ROCKS_MAINNET),
        ("zecrocks", Network::TestNetwork) => Some(ZEC_ROCKS_TESTNET),
        _ => return parse_host_list(server),
    };

    match preset {
        Some(servers) => Ok(servers.first().expect("preset is non-empty").clone()),
        None => Err(anyhow!(
            "lightwalletd preset '{server}' does not serve {network:?}"
        )),
    }
}

fn parse_host_list(s: &str) -> anyhow::Result<Server> {
    // Use the first entry of a comma-separated host:port list.
    let first = s.split(',').next().unwrap_or(s);
    let (host, port_str) = first
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid lightwalletd address '{first}', expected host:port"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid port in '{first}'"))?;
    Ok(Server::custom(host.to_string(), port))
}
