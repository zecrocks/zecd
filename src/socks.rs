//! SOCKS5 proxying for every outbound connection zecd makes.
//!
//! zecd dials exactly two upstreams - a zebrad JSON-RPC endpoint (plaintext HTTP/1.1, via
//! `hyper-util`'s legacy client) and a lightwalletd gRPC endpoint (tonic, usually over TLS) -
//! and `[backend] proxy` routes both through one SOCKS5 proxy. The shared piece is
//! [`SocksConnector`], a `tower_service::Service<Uri>` that both transports accept as a custom
//! connector: tonic via `Endpoint::connect_with_connector`, hyper via
//! `Client::builder(..).build(..)`.
//!
//! Two properties are load-bearing:
//!
//! - **The destination is handed to the proxy as a `host:port` string, never as a resolved
//!   `SocketAddr`** (SOCKS5h semantics). The proxy resolves it, so zecd leaks no DNS traffic and
//!   `.onion` destinations - which resolve nowhere locally - work.
//! - **TLS is layered *over* this connector by the transport, not by it.** The connector always
//!   yields a plaintext stream; tonic then applies whichever of the five `[backend]` TLS modes
//!   is configured, with SNI and certificate verification still pinned to the destination
//!   hostname. A proxy therefore cannot observe or MITM a TLS lightwalletd session.
//!
//! SOCKS username/password authentication is deliberately not supported (see
//! [`SocksProxy::parse`]).

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use hyper::Uri;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use tokio_socks::tcp::Socks5Stream;
use tower_service::Service;

/// How long a single SOCKS handshake (proxy connect + CONNECT exchange) may take.
///
/// This bounds a black-holed proxy *inside* the connector, which matters because hyper's
/// connection pool dials lazily: without it a hung proxy would stall a pooled request past the
/// caller's own deadline. Callers still layer their own bounds on top - `Server::connect_timeout`
/// for the lightwalletd dial, `chain::zebra`'s per-request timeout for the JSON-RPC path.
const SOCKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A resolved `[backend] proxy` setting: the address of a SOCKS5 proxy.
///
/// The host is kept as written (a hostname, an IPv4 literal, or an IPv6 literal) and resolved
/// only at connect time, so a proxy named in DNS does not have to be resolvable when the config
/// is parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksProxy {
    host: String,
    port: u16,
}

impl SocksProxy {
    /// Parse a `socks5://host:port` token.
    ///
    /// `socks5h://` is accepted as an alias: zecd always resolves the destination proxy-side, so
    /// the two schemes describe the same behaviour and both canonicalize to `socks5://`.
    ///
    /// Userinfo (`socks5://user:pass@host:port`) is **rejected** rather than ignored. zecd does
    /// not implement SOCKS username/password authentication, and silently dropping credentials
    /// would send an unauthenticated greeting to a proxy the operator believes is authenticated.
    pub fn parse(token: &str) -> anyhow::Result<SocksProxy> {
        let token = token.trim();
        let rest = match token.split_once("://") {
            Some(("socks5" | "socks5h", rest)) => rest,
            Some((scheme, _)) => {
                return Err(anyhow!(
                    "unsupported proxy scheme '{scheme}' in '{token}': zecd supports \
                     socks5:// (and socks5h://, an alias - the destination is always resolved \
                     by the proxy)"
                ));
            }
            None => {
                return Err(anyhow!(
                    "invalid proxy '{token}': expected socks5://host:port, e.g. \
                     socks5://127.0.0.1:9050"
                ));
            }
        };
        if rest.contains('@') {
            return Err(anyhow!(
                "invalid proxy '{token}': SOCKS username/password authentication is not \
                 supported, so credentials cannot be given here - use a proxy that authenticates \
                 by source address (a loopback or otherwise restricted listener)"
            ));
        }
        // A path/query would be silently ignored, and an operator who wrote one is describing
        // something this connector will not do.
        if let Some(i) = rest.find(['/', '?', '#']) {
            return Err(anyhow!(
                "invalid proxy '{token}': unexpected '{}' - a SOCKS proxy is addressed as \
                 host:port with no path",
                &rest[i..i + 1]
            ));
        }
        // Split host from port from the right, so an unbracketed IPv6 literal is diagnosed as a
        // bad port rather than silently mangled.
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => (host, port),
            None => {
                return Err(anyhow!(
                    "invalid proxy '{token}': missing ':port' (a SOCKS proxy has no default \
                     port; Tor's is 9050)"
                ));
            }
        };
        let host = host
            .strip_prefix('[')
            .map_or(host, |h| h.strip_suffix(']').unwrap_or(h));
        if host.is_empty() {
            return Err(anyhow!("invalid proxy '{token}': empty host"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow!("invalid proxy '{token}': '{port}' is not a port number"))?;
        if port == 0 {
            return Err(anyhow!(
                "invalid proxy '{token}': port 0 is not connectable"
            ));
        }
        Ok(SocksProxy {
            host: host.to_string(),
            port,
        })
    }

    /// The proxy host as configured (hostname or IP literal, without IPv6 brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for SocksProxy {
    /// The canonical `socks5://host:port` form, re-bracketing an IPv6 literal.
    ///
    /// This must round-trip through [`SocksProxy::parse`]: `config show` renders it and the
    /// renderer's output is fed back through a config resolve.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "socks5://[{}]:{}", self.host, self.port)
        } else {
            write!(f, "socks5://{}:{}", self.host, self.port)
        }
    }
}

/// A connector that dials every destination through a SOCKS5 proxy.
///
/// Implements `tower_service::Service<Uri>`, which is the connector trait for both transports
/// zecd uses (tonic's `connect_with_connector` and hyper-util's legacy client).
#[derive(Clone, Debug)]
pub struct SocksConnector {
    proxy: SocksProxy,
}

impl SocksConnector {
    /// A connector dialing through `proxy`.
    pub fn new(proxy: SocksProxy) -> SocksConnector {
        SocksConnector { proxy }
    }
}

/// The stream both connector arms yield: `HttpConnector`'s own response type, so the two are
/// interchangeable to hyper, and the adapter tonic needs over a tokio socket.
type ProxiedStream = TokioIo<tokio::net::TcpStream>;

/// The boxed error both connector arms report, matching what hyper and tonic expect.
type ConnectError = Box<dyn std::error::Error + Send + Sync>;

impl Service<Uri> for SocksConnector {
    type Response = ProxiedStream;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Stateless - a fresh proxy connection per call, so there is nothing to wait for.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        Box::pin(async move {
            let host = uri.host().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("no host in destination uri '{uri}'"),
                )
            })?;
            // Both zecd dial sites always carry an explicit port; the scheme default is a
            // backstop so a port-less uri cannot silently become port 0.
            let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });
            // The destination is passed as a *string*: the proxy resolves it, which is what
            // keeps DNS off this host and makes `.onion` destinations reachable.
            let target = format!("{host}:{port}");
            let stream = tokio::time::timeout(
                SOCKS_CONNECT_TIMEOUT,
                Socks5Stream::connect((proxy.host(), proxy.port()), target.as_str()),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "SOCKS5 proxy {proxy} did not complete the connection to {target} \
                         within {SOCKS_CONNECT_TIMEOUT:?}"
                    ),
                )
            })?
            .map_err(|e| {
                std::io::Error::other(format!(
                    "SOCKS5 proxy {proxy} could not connect to {target}: {e}"
                ))
            })?;
            Ok(TokioIo::new(stream.into_inner()))
        })
    }
}

/// The zebra JSON-RPC client's connector: the stock TCP one, or the SOCKS one.
///
/// An enum rather than a boxed service so the unproxied path - the overwhelmingly common
/// deployment, a loopback zebrad - keeps dialing through `HttpConnector` exactly as before,
/// with no added indirection.
#[derive(Clone, Debug)]
pub enum MaybeSocksConnector {
    /// Dial the destination directly.
    Direct(HttpConnector),
    /// Dial the destination through a SOCKS5 proxy.
    Socks(SocksConnector),
}

impl MaybeSocksConnector {
    /// The connector for a `[backend] proxy` setting.
    pub fn new(proxy: Option<&SocksProxy>) -> MaybeSocksConnector {
        match proxy {
            Some(proxy) => MaybeSocksConnector::Socks(SocksConnector::new(proxy.clone())),
            None => MaybeSocksConnector::Direct(HttpConnector::new()),
        }
    }
}

impl Service<Uri> for MaybeSocksConnector {
    type Response = ProxiedStream;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            MaybeSocksConnector::Direct(c) => c.poll_ready(cx).map_err(Into::into),
            MaybeSocksConnector::Socks(c) => c.poll_ready(cx),
        }
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        match self {
            MaybeSocksConnector::Direct(c) => {
                let fut = c.call(uri);
                Box::pin(async move { fut.await.map_err(Into::into) })
            }
            MaybeSocksConnector::Socks(c) => c.call(uri),
        }
    }
}

/// A minimal in-process SOCKS5 server for tests.
///
/// Speaks just enough of RFC 1928 to accept a no-auth CONNECT, and always forwards to one fixed
/// upstream regardless of the destination asked for. That rewrite is the point: a test can name
/// an unresolvable host like `zebrad.test.invalid:1`, and the connection succeeding proves the
/// bytes went through the proxy rather than out a direct dial. Every requested target is
/// recorded, so a test can also assert *what* was asked for - which is how proxy-side DNS
/// (the destination sent as a name, not a resolved address) is pinned.
#[cfg(test)]
pub(crate) mod test_proxy {
    use std::io;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    /// A running fake SOCKS5 proxy. Dropping it leaves the accept task to die with the runtime.
    pub(crate) struct TestProxy {
        addr: SocketAddr,
        targets: Arc<Mutex<Vec<String>>>,
    }

    impl TestProxy {
        /// Start a proxy on loopback that forwards every CONNECT to `upstream`.
        pub(crate) async fn start(upstream: SocketAddr) -> TestProxy {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let targets = Arc::new(Mutex::new(Vec::new()));
            let recorded = targets.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((client, _)) = listener.accept().await else {
                        return;
                    };
                    let recorded = recorded.clone();
                    tokio::spawn(async move {
                        let _ = serve(client, upstream, recorded).await;
                    });
                }
            });
            TestProxy { addr, targets }
        }

        /// The proxy token to configure zecd with.
        pub(crate) fn proxy(&self) -> super::SocksProxy {
            super::SocksProxy::parse(&format!("socks5://{}:{}", self.addr.ip(), self.addr.port()))
                .unwrap()
        }

        /// Every destination requested so far, in `host:port` form as the client sent it.
        pub(crate) fn targets(&self) -> Vec<String> {
            self.targets.lock().unwrap().clone()
        }
    }

    /// One client: no-auth handshake, CONNECT, then splice to the fixed upstream.
    async fn serve(
        mut client: TcpStream,
        upstream: SocketAddr,
        targets: Arc<Mutex<Vec<String>>>,
    ) -> io::Result<()> {
        // Greeting: VER, NMETHODS, METHODS... - answer "no authentication required".
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(io::Error::other("not SOCKS5"));
        }
        let mut methods = vec![0u8; head[1] as usize];
        client.read_exact(&mut methods).await?;
        client.write_all(&[0x05, 0x00]).await?;

        // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
        let mut req = [0u8; 4];
        client.read_exact(&mut req).await?;
        if req[1] != 0x01 {
            return Err(io::Error::other("only CONNECT is implemented"));
        }
        let host = match req[3] {
            0x01 => {
                let mut octets = [0u8; 4];
                client.read_exact(&mut octets).await?;
                std::net::Ipv4Addr::from(octets).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                client.read_exact(&mut name).await?;
                String::from_utf8_lossy(&name).into_owned()
            }
            0x04 => {
                let mut octets = [0u8; 16];
                client.read_exact(&mut octets).await?;
                std::net::Ipv6Addr::from(octets).to_string()
            }
            other => return Err(io::Error::other(format!("bad ATYP {other}"))),
        };
        let mut port = [0u8; 2];
        client.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        targets.lock().unwrap().push(format!("{host}:{port}"));

        // Success, with a dummy IPv4 bind address (the client ignores it).
        let mut server = TcpStream::connect(upstream).await?;
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut server).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::test_proxy::TestProxy;
    use super::*;

    #[test]
    fn parse_accepts_hostnames_and_ip_literals() {
        let p = SocksProxy::parse("socks5://127.0.0.1:9050").unwrap();
        assert_eq!((p.host(), p.port()), ("127.0.0.1", 9050));
        let p = SocksProxy::parse("socks5://tor.internal:1080").unwrap();
        assert_eq!((p.host(), p.port()), ("tor.internal", 1080));
        // An IPv6 literal must be bracketed, and the brackets are not part of the host.
        let p = SocksProxy::parse("socks5://[::1]:9050").unwrap();
        assert_eq!((p.host(), p.port()), ("::1", 9050));
    }

    #[test]
    fn parse_canonicalizes_the_socks5h_alias() {
        // Both schemes mean the same thing here (the proxy always resolves the destination), so
        // socks5h is accepted and renders back as socks5.
        let p = SocksProxy::parse("socks5h://127.0.0.1:9050").unwrap();
        assert_eq!(p, SocksProxy::parse("socks5://127.0.0.1:9050").unwrap());
        assert_eq!(p.to_string(), "socks5://127.0.0.1:9050");
    }

    #[test]
    fn display_round_trips_through_parse() {
        // `config show` renders this and its output is re-resolved, so the rendered form must
        // parse back to an identical value.
        for token in [
            "socks5://127.0.0.1:9050",
            "socks5://tor.internal:1080",
            "socks5://[::1]:9050",
            "socks5h://[fd00::1]:1080",
        ] {
            let parsed = SocksProxy::parse(token).unwrap();
            let rendered = parsed.to_string();
            assert_eq!(
                SocksProxy::parse(&rendered).unwrap(),
                parsed,
                "{token} rendered as {rendered}"
            );
            assert_eq!(SocksProxy::parse(&rendered).unwrap().to_string(), rendered);
        }
    }

    #[test]
    fn parse_rejects_unusable_tokens() {
        // Each message must name what is wrong, since it surfaces through `config check`.
        let cases = [
            ("http://127.0.0.1:8080", "unsupported proxy scheme"),
            ("socks4://127.0.0.1:9050", "unsupported proxy scheme"),
            ("127.0.0.1:9050", "expected socks5://host:port"),
            ("socks5://127.0.0.1", "missing ':port'"),
            ("socks5://:9050", "empty host"),
            ("socks5://127.0.0.1:0", "port 0"),
            ("socks5://127.0.0.1:notaport", "is not a port number"),
            ("socks5://user:pass@127.0.0.1:9050", "not supported"),
            ("socks5://127.0.0.1:9050/path", "unexpected '/'"),
        ];
        for (token, needle) in cases {
            let err = SocksProxy::parse(token).unwrap_err().to_string();
            assert!(
                err.contains(needle),
                "parsing {token} should mention {needle:?}, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn connector_dials_through_the_proxy_and_resolves_the_destination_proxy_side() {
        // An echo server standing in for the upstream.
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let proxy = TestProxy::start(echo_addr).await;
        let mut connector = SocksConnector::new(proxy.proxy());
        // A name that resolves nowhere: reaching the echo server at all proves the destination
        // was handed to the proxy rather than resolved here.
        let uri: Uri = "http://target.test.invalid:9/".parse().unwrap();
        let stream = connector.call(uri).await.unwrap();

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut io = stream.into_inner();
        io.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // And the proxy was asked for the *name*, not an address - the socks5h property.
        assert_eq!(proxy.targets(), vec!["target.test.invalid:9".to_string()]);
    }

    #[tokio::test]
    async fn maybe_connector_dials_directly_when_no_proxy_is_configured() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let mut connector = MaybeSocksConnector::new(None);
        let uri: Uri = format!("http://{echo_addr}/").parse().unwrap();
        // The unproxied arm still dials, and does so without any proxy in the picture.
        assert!(connector.call(uri).await.is_ok());
    }

    #[test]
    fn parse_ignores_surrounding_whitespace() {
        assert_eq!(
            SocksProxy::parse("  socks5://127.0.0.1:9050\n").unwrap(),
            SocksProxy::parse("socks5://127.0.0.1:9050").unwrap()
        );
    }
}
