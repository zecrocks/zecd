//! SOCKS5 connector for routing gRPC connections through an external proxy.
//!
//! Ported from `zcash-devtool/src/socks.rs`. Lets lightwalletd connections be routed through any
//! SOCKS5 proxy, including:
//! - **Tor** (for `.onion` endpoints and network-level privacy) - point at Tor's SOCKS port
//!   (`127.0.0.1:9050` by default);
//! - **Nym** mixnet;
//! - any other SOCKS5-compatible proxy.
//!
//! DNS resolution is delegated to the proxy (SOCKS5 connect-by-name), which is required for
//! `.onion` addresses and avoids leaking the target hostname to the local resolver.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio_socks::tcp::Socks5Stream;
use tonic::transport::Uri;
use tower::Service;

/// A connector that routes connections through a SOCKS5 proxy.
///
/// Implements `tower::Service<Uri>` for use with tonic's `Endpoint::connect_with_connector()`.
/// tonic still layers TLS over the returned stream when the endpoint has a `tls_config`, so the
/// proxy only carries the encrypted bytes for remote (TLS) endpoints.
#[derive(Clone)]
pub struct SocksConnector {
    proxy_addr: SocketAddr,
}

impl SocksConnector {
    /// Creates a new SOCKS connector targeting the given proxy address.
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self { proxy_addr }
    }
}

impl Service<Uri> for SocksConnector {
    type Response = TokioIo<tokio::net::TcpStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Stateless connector - always ready.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let proxy_addr = self.proxy_addr;

        Box::pin(async move {
            let host = uri.host().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing host in URI")
            })?;

            // tonic strips the default port from the URI, so fall back to the TLS port.
            let port = uri.port_u16().unwrap_or(443);
            let target = format!("{host}:{port}");

            // Connect through the SOCKS5 proxy, bounding the dial so a hung proxy can't stall the
            // caller. DNS resolution happens on the proxy side (critical for `.onion` addresses).
            let socks_stream = tokio::time::timeout(
                Duration::from_secs(30),
                Socks5Stream::connect(proxy_addr, target.as_str()),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS connection timed out")
            })??;

            // Adapt the proxied stream to tonic/hyper's I/O traits.
            Ok(TokioIo::new(socks_stream.into_inner()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Accept one connection and play just enough SOCKS5 server to satisfy `tokio-socks`:
    /// negotiate the no-auth method, read the CONNECT request, reply success - and return the
    /// target the client asked the proxy to reach. No real upstream connection is made, so the
    /// test stays offline and deterministic; it exercises the connector's actual SOCKS5 dial.
    async fn fake_socks5_capture_target(listener: TcpListener) -> std::io::Result<String> {
        let (mut sock, _) = listener.accept().await?;

        // Greeting: VER, NMETHODS, METHODS[NMETHODS].
        let mut greeting = [0u8; 2];
        sock.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 0x05, "SOCKS version must be 5");
        let mut methods = vec![0u8; greeting[1] as usize];
        sock.read_exact(&mut methods).await?;
        // Select "no authentication required".
        sock.write_all(&[0x05, 0x00]).await?;

        // Request: VER, CMD, RSV, ATYP, then the address.
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await?;
        assert_eq!(req[0], 0x05);
        assert_eq!(req[1], 0x01, "CMD must be CONNECT");
        let target = match req[3] {
            // Domain name (ATYP=3): proxy-side DNS - what we expect for host names / `.onion`.
            0x03 => {
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await?;
                let mut domain = vec![0u8; len[0] as usize];
                sock.read_exact(&mut domain).await?;
                let mut port = [0u8; 2];
                sock.read_exact(&mut port).await?;
                format!(
                    "{}:{}",
                    String::from_utf8_lossy(&domain),
                    u16::from_be_bytes(port)
                )
            }
            // IPv4 (ATYP=1), handled for completeness.
            0x01 => {
                let mut addr = [0u8; 4];
                sock.read_exact(&mut addr).await?;
                let mut port = [0u8; 2];
                sock.read_exact(&mut port).await?;
                format!(
                    "{}.{}.{}.{}:{}",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    u16::from_be_bytes(port)
                )
            }
            other => panic!("unexpected SOCKS5 ATYP {other}"),
        };

        // Reply success with a dummy bound address (VER, REP=0, RSV, ATYP=IPv4, 0.0.0.0:0).
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        Ok(target)
    }

    /// Drive `SocksConnector::call` against the fake proxy and return the target the proxy was
    /// asked to reach.
    async fn connect_via_fake_proxy(uri: &str) -> String {
        use tower::Service;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_socks5_capture_target(listener));

        let mut connector = SocksConnector::new(proxy_addr);
        let conn = connector.call(uri.parse().unwrap()).await;
        assert!(
            conn.is_ok(),
            "SOCKS5 negotiation should succeed: {:?}",
            conn.err()
        );

        server
            .await
            .unwrap()
            .expect("fake SOCKS5 server ran cleanly")
    }

    #[tokio::test]
    async fn connector_negotiates_socks5_and_targets_uri_host_by_name() {
        // The connector must dial the proxy, complete the handshake, and ask it (by name, so DNS
        // happens proxy-side) for exactly the URI's host:port.
        let target = connect_via_fake_proxy("https://lightwalletd.example:9067").await;
        assert_eq!(target, "lightwalletd.example:9067");
    }

    #[tokio::test]
    async fn connector_falls_back_to_tls_port_when_uri_omits_it() {
        // tonic drops the default port from the URI; the connector must restore 443.
        let target = connect_via_fake_proxy("https://zec.rocks").await;
        assert_eq!(target, "zec.rocks:443");
    }
}
