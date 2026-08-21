//! Upstream-endpoint management: resolving the configured `server` token into a single
//! endpoint - a local zebrad JSON-RPC server ("full mode") or a lightwalletd gRPC server
//! ("light mode") - and dialing it.
//!
//! Token grammar (`[backend] server` / `--server`):
//!  * `zebra` - the default: a local zebrad at `127.0.0.1` on the recommended RPC port.
//!  * `zebra://host:port` - an explicit zebrad JSON-RPC endpoint (plaintext HTTP, local-only
//!    by policy - see the cleartext gate in `chain::zebra`).
//!  * `zecrocks` - the zec.rocks public lightwalletd preset (`zec.rocks:443` mainnet,
//!    `testnet.zec.rocks:443` testnet), TLS.
//!  * `https://host[:port]` - a lightwalletd endpoint, TLS forced on.
//!  * `http://host:port` - a lightwalletd endpoint, TLS forced off (the regtest harness's
//!    local plaintext lightwalletd; refused toward public hosts unless
//!    `allow_remote_cleartext`).
//!  * bare `host:port` - a lightwalletd endpoint; TLS decided by the locality heuristic
//!    (loopback/private-network plaintext, public TLS), overridable via `[backend] tls`.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tonic::transport::{Channel, ClientTlsConfig};

use crate::chain::lwd::LwdSource;
use crate::chain::zebra::{host_is_local, CleartextPolicy, ZebraAuth, ZebraSource};
use crate::chain::AnySource;
use crate::network::ZNetwork;

/// The default upstream's local zebrad JSON-RPC ports (the ports named by
/// `config::default_server`). zebra ships with RPC disabled - there is no upstream default port
/// to inherit - and the zcashd-convention RPC ports (8232/18232) are zecd's own, so the
/// recommended `rpc.listen_addr` for a zebrad serving zecd sits next to zebra's P2P ports
/// (8233/18233) instead.
pub const ZEBRA_RPC_PORT_MAIN: u16 = 8234;
pub const ZEBRA_RPC_PORT_TEST: u16 = 18234;

/// The `zecrocks` public lightwalletd preset.
const ZEC_ROCKS_MAINNET: (&str, u16) = ("zec.rocks", 443);
const ZEC_ROCKS_TESTNET: (&str, u16) = ("testnet.zec.rocks", 443);

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

/// A SHA-256 fingerprint of a leaf certificate's DER encoding - what `openssl x509 -noout
/// -fingerprint -sha256` prints, and what `[backend] tls_pinned_sha256` accepts.
///
/// The whole certificate is hashed rather than its public key (RFC 7469-style SPKI pinning):
/// the fingerprint is then something an operator can produce with stock tooling and compare by
/// eye, at the cost of having to re-pin when the certificate is renewed. `tls_pinned_sha256`
/// takes a list precisely so a renewal can be pinned alongside the outgoing certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertFingerprint([u8; 32]);

impl CertFingerprint {
    /// Parse `AB:CD:...` or bare hex, any case. Colons (openssl's output) and surrounding
    /// whitespace are optional.
    pub fn parse(s: &str) -> anyhow::Result<CertFingerprint> {
        let hex_only: String = s.trim().chars().filter(|c| *c != ':').collect();
        if hex_only.len() != 64 {
            return Err(anyhow!(
                "invalid SHA-256 certificate fingerprint '{s}': expected 64 hex digits \
                 (32 bytes), with or without ':' separators, got {}",
                hex_only.len()
            ));
        }
        let bytes = hex::decode(&hex_only)
            .map_err(|e| anyhow!("invalid SHA-256 certificate fingerprint '{s}': {e}"))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(CertFingerprint(out))
    }

    /// The fingerprint of a presented certificate.
    fn of(cert: &CertificateDer<'_>) -> CertFingerprint {
        use sha2::{Digest as _, Sha256};
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(cert.as_ref()));
        CertFingerprint(out)
    }

    /// Constant-time equality. A pin comparison is not a secret-dependent operation in any
    /// obvious threat model (the fingerprint is public data), but the compare is free and this
    /// keeps it from becoming an oracle if a pin is ever derived from something private.
    fn matches(&self, other: &CertFingerprint) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Display for CertFingerprint {
    /// Colon-separated uppercase hex, byte-for-byte what openssl prints, so an operator can
    /// paste a rejected fingerprint straight into `tls_pinned_sha256` after verifying it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

/// The resolved `[backend]` TLS settings for a lightwalletd endpoint. Every field is
/// independently optional; see [`Server::connect_lwd`] for how they compose.
#[derive(Clone, Debug, Default)]
pub struct TlsOptions {
    /// `Some(true/false)` forces TLS on/off; `None` uses the locality heuristic. An explicit
    /// `https://`/`http://` scheme sets this at resolve time and wins over the config value.
    pub force_tls: Option<bool>,
    /// Which public root store to trust (`tls_roots`).
    pub roots: TlsRoots,
    /// Accept any certificate (`tls_insecure_skip_verify`). Mutually exclusive with the two
    /// below, which authenticate the server rather than giving up on doing so.
    pub insecure_skip_verify: bool,
    /// PEM bytes of a private CA (`tls_ca_file`), read at config load so an unreadable file
    /// fails startup rather than silently falling back to weaker trust.
    pub ca_pem: Option<Vec<u8>>,
    /// Acceptable leaf-certificate fingerprints (`tls_pinned_sha256`). Non-empty means the
    /// server's certificate must be one of these.
    pub pins: Vec<CertFingerprint>,
}

impl TlsOptions {
    /// Whether any setting here authenticates or refuses the peer, and so would be silently
    /// void on a plaintext connection.
    pub fn requires_tls(&self) -> bool {
        self.ca_pem.is_some() || !self.pins.is_empty()
    }
}

/// A rustls server-certificate verifier that accepts **any** certificate chain, for
/// `[backend] tls_insecure_skip_verify`. It skips exactly what a CA-signed chain would prove -
/// that the peer's certificate chains to a trusted root and matches the hostname - so the
/// connection stays encrypted but becomes *unauthenticated*: an on-path attacker who can
/// redirect the TCP connection can present their own certificate and read/rewrite every query.
/// The intended use is a self-signed lightwalletd the operator runs themselves; prefer
/// `tls_roots = "native"` with the CA installed in the OS trust store where that is possible.
///
/// Handshake *signatures* are still verified against the presented key (the standard shape for
/// this verifier): that costs nothing, keeps the handshake internally consistent, and the
/// authentication decision being bypassed lives entirely in `verify_server_cert`.
#[derive(Debug)]
struct NoServerCertVerification {
    /// Signature algorithms used for the TLS 1.2/1.3 handshake-signature checks.
    algorithms: WebPkiSupportedAlgorithms,
}

impl NoServerCertVerification {
    fn new() -> Self {
        // `ring`, matching tonic's `tls-ring` feature - the one crypto provider this build
        // links. Taken directly rather than via
        // `CryptoProvider::get_default()`, which is unset here: tonic 0.14 selects its provider
        // internally with `builder_with_provider` and never installs a process-wide default.
        NoServerCertVerification {
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A rustls verifier that requires the server's leaf certificate to match one of the
/// configured `[backend] tls_pinned_sha256` fingerprints.
///
/// With `chain` set (a `tls_ca_file` was also configured) the certificate must *additionally*
/// chain to that CA and match the hostname, so pinning is defense in depth over a private PKI.
/// With `chain` unset the pin is the whole identity: no chain, hostname, or expiry check runs,
/// which is what makes a bare self-signed certificate usable without weakening it to
/// `tls_insecure_skip_verify`. That difference is the point of the two knobs, so keep both
/// paths.
#[derive(Debug)]
struct PinnedServerCertVerification {
    /// Any one of these matching the presented leaf is accepted.
    pins: Vec<CertFingerprint>,
    /// Optional full webpki validation against the private CA, run after the pin matches.
    chain: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    /// Signature algorithms for the handshake-signature checks.
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedServerCertVerification {
    /// Build the verifier, compiling `ca_pem` (when given) into the trust anchors the chain
    /// check runs against.
    ///
    /// Note that in this mode the private CA is the *only* trust anchor - the public root store
    /// (`tls_roots`) is deliberately not consulted. Pinning plus a private CA describes a
    /// self-contained PKI, and quietly trusting every public CA alongside it would widen what
    /// the operator asked for.
    fn new(
        pins: Vec<CertFingerprint>,
        ca_pem: Option<&[u8]>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> anyhow::Result<Self> {
        let algorithms = provider.signature_verification_algorithms;
        let chain = match ca_pem {
            Some(pem) => {
                let mut roots = rustls::RootCertStore::empty();
                let (added, ignored) = roots.add_parsable_certificates(read_pem_certificates(pem)?);
                if added == 0 {
                    return Err(anyhow!(
                        "[backend] tls_ca_file contains no usable certificate ({ignored} \
                         unparsable)"
                    ));
                }
                Some(
                    rustls::client::WebPkiServerVerifier::builder_with_provider(
                        Arc::new(roots),
                        provider,
                    )
                    .build()
                    .map_err(|e| anyhow!("building the [backend] tls_ca_file verifier: {e}"))?,
                )
            }
            None => None,
        };
        Ok(PinnedServerCertVerification {
            pins,
            chain,
            algorithms,
        })
    }
}

impl ServerCertVerifier for PinnedServerCertVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = CertFingerprint::of(end_entity);
        if !self.pins.iter().any(|pin| pin.matches(&presented)) {
            // Name the fingerprint actually presented: without it an operator has no way to
            // bootstrap the pin or tell a rotation from an attack.
            return Err(rustls::Error::General(format!(
                "server certificate fingerprint {presented} matches no [backend] \
                 tls_pinned_sha256 entry; if the server's certificate was replaced, verify this \
                 fingerprint out of band and add it to the list"
            )));
        }
        match &self.chain {
            Some(chain) => {
                chain.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            }
            None => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Parse the certificates out of a PEM bundle (`[backend] tls_ca_file`).
fn read_pem_certificates(pem: &[u8]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject as _;
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("parsing [backend] tls_ca_file: {e}"))
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
    /// lightwalletd TLS settings (`[backend] tls`/`tls_roots`/`tls_ca_file`/
    /// `tls_pinned_sha256`/`tls_insecure_skip_verify`). Unused by `zebra://` endpoints, which
    /// are always plaintext HTTP.
    tls: TlsOptions,
    /// zebrad RPC credentials (`[zebra]` config); never applied to lightwalletd endpoints
    /// (lightwalletd has no client auth - the credentials must not ride to a foreign host).
    zebra_auth: ZebraAuth,
    /// Locality policy (`[backend] rfc1918_is_local` / `allow_remote_cleartext`). Gates
    /// credentialed plaintext to zebra, and *any* plaintext to a lightwalletd (query privacy).
    cleartext_policy: CleartextPolicy,
    /// Operator assertion that this lightwalletd serves transparent data in compact blocks
    /// (`[backend] assume_transparent_in_compact_blocks`), overriding the capability probe.
    /// Unused by `zebra://` endpoints, which always cover it.
    assume_transparent_in_compact_blocks: bool,
}

impl Server {
    fn new(host: Cow<'static, str>, port: u16, kind: ServerKind, network: ZNetwork) -> Self {
        Server {
            host,
            port,
            kind,
            network,
            tls: TlsOptions::default(),
            zebra_auth: ZebraAuth::default(),
            cleartext_policy: CleartextPolicy::default(),
            assume_transparent_in_compact_blocks: false,
        }
    }

    pub fn kind(&self) -> ServerKind {
        self.kind
    }

    /// Whether the lightwalletd dial uses TLS: the forced setting when present, else the
    /// locality heuristic - loopback/private-network hosts (docker/k8s/LAN, where a public
    /// CA-signed cert is impossible) dial plaintext, everything else TLS.
    fn use_tls(&self) -> bool {
        self.tls
            .force_tls
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

    /// Run the connect-time checks that need no network, so a misconfiguration that would leave
    /// the daemon retrying a connect it can never complete is reportable up front - this is what
    /// `zecd config check` calls. [`connect_timeout`](Server::connect_timeout) reaches the same
    /// verdicts through the same helpers, so the two cannot drift.
    pub fn preflight(&self) -> anyhow::Result<()> {
        match self.kind {
            ServerKind::Lightwalletd => {
                if !self.use_tls() {
                    self.check_plaintext_lwd()?;
                }
            }
            ServerKind::ZebraRpc => {
                self.zebra_auth.validate()?;
                crate::chain::zebra::cleartext_gate(
                    &self.host,
                    self.zebra_auth.is_configured(),
                    self.cleartext_policy,
                )?;
            }
        }
        Ok(())
    }

    /// The refusals that apply to a lightwalletd endpoint dialing *without* TLS. Split out of
    /// [`connect_lwd`](Server::connect_lwd) so [`preflight`](Server::preflight) runs exactly the
    /// same checks.
    fn check_plaintext_lwd(&self) -> anyhow::Result<()> {
        // A pin or a private CA on an endpoint that dials plaintext is a configuration the
        // operator cannot have meant: the settings that would authenticate the server are
        // simply never consulted. Refuse rather than connect with them silently void.
        // (`tls = "no"` and an `http://` token are caught earlier, at config load; this
        // catches the locality heuristic resolving a bare `host:port` to plaintext.)
        if self.tls.requires_tls() {
            return Err(anyhow!(
                "[backend] tls_pinned_sha256/tls_ca_file are set, but {}:{} resolved to a \
                 plaintext connection, where neither can be checked; set tls = \"yes\" (or \
                 use an https:// endpoint) to require TLS",
                self.host,
                self.port
            ));
        }
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
        Ok(())
    }

    /// Dial this lightwalletd server (TCP/TLS connect + capability probe).
    async fn connect_lwd(&self) -> anyhow::Result<LwdSource> {
        if !self.use_tls() {
            self.check_plaintext_lwd()?;
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
            // Three ways to authenticate the peer, in decreasing strictness. A custom verifier
            // *replaces* rustls' default one, so tonic rejects combining it with any root-store
            // method - which is why the pinned and insecure arms pass `tls` untouched and the
            // pinned arm compiles `tls_ca_file` into its own trust anchors instead.
            match (&self.tls.pins[..], self.tls.insecure_skip_verify) {
                // Pinned: the leaf must be one of the configured fingerprints, plus a full
                // chain check against `tls_ca_file` when one is set.
                (pins, _) if !pins.is_empty() => {
                    tracing::info!(
                        "lightwalletd {}:{} TLS is pinned to {} certificate fingerprint(s){}",
                        self.host,
                        self.port,
                        pins.len(),
                        if self.tls.ca_pem.is_some() {
                            ", validated against [backend] tls_ca_file"
                        } else {
                            " (the pin is the whole identity: no chain, hostname, or expiry check)"
                        }
                    );
                    let verifier = PinnedServerCertVerification::new(
                        pins.to_vec(),
                        self.tls.ca_pem.as_deref(),
                        rustls::crypto::ring::default_provider().into(),
                    )?;
                    endpoint.tls_config_with_verifier(tls, Arc::new(verifier))?
                }
                // Unpinned but verified: the public root store, plus `tls_ca_file` as an
                // additional trust anchor when set. Standard validation throughout.
                (_, false) => {
                    let tls = match self.tls.roots {
                        TlsRoots::Native => tls.with_native_roots(),
                        TlsRoots::Webpki => tls.with_webpki_roots(),
                    };
                    let tls = match &self.tls.ca_pem {
                        Some(pem) => {
                            tls.ca_certificate(tonic::transport::Certificate::from_pem(pem))
                        }
                        None => tls,
                    };
                    endpoint.tls_config(tls)?
                }
                // Unauthenticated.
                (_, true) => {
                    tracing::warn!(
                        "connecting to lightwalletd {}:{} with TLS certificate verification \
                         DISABLED ([backend] tls_insecure_skip_verify): encrypted but \
                         unauthenticated - an on-path attacker can impersonate this server. \
                         Prefer tls_pinned_sha256 for a self-signed certificate",
                        self.host,
                        self.port
                    );
                    endpoint
                        .tls_config_with_verifier(tls, Arc::new(NoServerCertVerification::new()))?
                }
            }
        } else {
            endpoint
        };
        let channel = endpoint.connect().await?;
        LwdSource::connect(channel, self.assume_transparent_in_compact_blocks).await
    }

    /// Connect with a default dial timeout. Convenience for tests; production callers use
    /// [`connect_timeout`](Server::connect_timeout).
    #[cfg(test)]
    pub async fn connect(&self) -> anyhow::Result<AnySource> {
        self.connect_timeout(Duration::from_secs(30)).await
    }
}

/// Resolve `[backend] server` into an endpoint carrying every setting that applies to it -
/// `[zebra]` credentials, the locality/cleartext policy, the TLS options, and the transparent
/// capability assertion. The daemon builds each wallet's endpoint this way, and `zecd config
/// check` inspects the same value, so what the check reports is what the daemon would dial.
pub fn resolve_configured(config: &crate::config::AppConfig) -> anyhow::Result<Server> {
    let mut server = resolve(&config.backend.server, config.network)?;
    apply_zebra_auth(&mut server, &config.zebra.auth());
    apply_cleartext_policy(
        &mut server,
        CleartextPolicy {
            rfc1918_is_local: config.backend.rfc1918_is_local,
            allow_remote_cleartext: config.backend.allow_remote_cleartext,
        },
    );
    apply_tls(&mut server, config.backend.tls_options());
    apply_transparent_capability_override(
        &mut server,
        config.backend.assume_transparent_in_compact_blocks,
    );
    Ok(server)
}

/// Resolve the upstream endpoint for one wallet: its own `[wallets.<name>]` `server`/TLS
/// overrides, falling back field-by-field to the global `[backend]`. The `[zebra]`
/// credentials and the cleartext-locality policy stay global - they are properties of the
/// deployment, not of one endpoint.
///
/// This is what lets a single daemon serve, say, a zebra-backed spending wallet alongside a
/// lightwalletd-backed watch-only replica. Every per-endpoint capability check (the
/// lightwalletd transparent-capability probe, the cleartext gate) is already per-actor, so it
/// follows the wallet's own server without further plumbing.
pub fn resolve_for_wallet(
    config: &crate::config::AppConfig,
    entry: &crate::config::WalletEntry,
) -> anyhow::Result<Server> {
    let backend = entry.backend.effective(&config.backend);
    // The token grammar is resolved from the wallet's own entry, so the upstream a wallet
    // dials is decided here and nothing above this function reads the global config again.
    let mut server = match entry.coin {
        crate::coin::Coin::Zcash => resolve(&backend.server, entry.zcash_network())?,
    };
    apply_zebra_auth(&mut server, &config.zebra.auth());
    apply_cleartext_policy(
        &mut server,
        CleartextPolicy {
            rfc1918_is_local: backend.rfc1918_is_local,
            allow_remote_cleartext: backend.allow_remote_cleartext,
        },
    );
    apply_tls(&mut server, backend.tls_options());
    apply_transparent_capability_override(
        &mut server,
        backend.assume_transparent_in_compact_blocks,
    );
    Ok(server)
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

/// Set the lightwalletd TLS options (the `[backend] tls*` keys) on the resolved endpoint. The
/// scheme prefix wins over the configured `tls` mode (an explicit `https://`/`http://` already
/// forced it at resolve time), so that one field is merged rather than overwritten.
pub fn apply_tls(server: &mut Server, opts: TlsOptions) {
    let scheme_forced = server.tls.force_tls;
    server.tls = opts;
    if let Some(forced) = scheme_forced {
        server.tls.force_tls = Some(forced);
    }
}

/// Record the operator's assertion that this lightwalletd serves transparent data in compact
/// blocks (`[backend] assume_transparent_in_compact_blocks`), overriding the connect-time
/// capability probe. A no-op for a `zebra://` endpoint, whose block scan always covers it.
pub fn apply_transparent_capability_override(server: &mut Server, assume: bool) {
    if assume && server.kind != ServerKind::Lightwalletd {
        tracing::warn!(
            "[backend] assume_transparent_in_compact_blocks is set but the upstream is not a \
             lightwalletd; ignoring (this backend already covers transparent data)"
        );
        return;
    }
    server.assume_transparent_in_compact_blocks = assume;
}

/// Resolve the configured `server` token into a single upstream endpoint. See the module doc
/// for the accepted grammar.
pub fn resolve(server: &str, network: ZNetwork) -> anyhow::Result<Server> {
    if server == "zebra" {
        let port = match network {
            ZNetwork::Main => ZEBRA_RPC_PORT_MAIN,
            ZNetwork::Test | ZNetwork::Regtest(_) => ZEBRA_RPC_PORT_TEST,
        };
        return Ok(Server::new(
            Cow::Borrowed("127.0.0.1"),
            port,
            ServerKind::ZebraRpc,
            network,
        ));
    }
    if server == "zecrocks" {
        let (host, port) = match network {
            ZNetwork::Main => ZEC_ROCKS_MAINNET,
            ZNetwork::Test => ZEC_ROCKS_TESTNET,
            ZNetwork::Regtest(_) => {
                return Err(anyhow!(
                    "the 'zecrocks' preset serves mainnet and testnet only (regtest needs a \
                     local upstream)"
                ))
            }
        };
        let mut s = Server::new(Cow::Borrowed(host), port, ServerKind::Lightwalletd, network);
        s.tls.force_tls = Some(true);
        return Ok(s);
    }
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
        None => {
            return Err(anyhow!(
                "invalid endpoint '{server}', expected host:port (or zebra | zecrocks | \
                 zebra://host:port | https://host[:port] | http://host:port)"
            ))
        }
    };
    if host.is_empty() {
        return Err(anyhow!("invalid endpoint '{server}': empty host"));
    }
    let mut s = Server::new(Cow::Owned(host.to_string()), port, kind, network);
    s.tls.force_tls = force_tls;
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
    fn zecrocks_preset_resolves_per_network_with_tls() {
        let main = resolve("zecrocks", ZNetwork::Main).unwrap();
        assert_eq!(main.host.as_ref(), "zec.rocks");
        assert_eq!(main.port, 443);
        assert_eq!(main.kind, ServerKind::Lightwalletd);
        assert!(main.use_tls(), "the public preset always dials TLS");

        let test = resolve("zecrocks", ZNetwork::Test).unwrap();
        assert_eq!(test.host.as_ref(), "testnet.zec.rocks");
        assert_eq!(test.port, 443);

        // No public preset serves a private regtest chain.
        assert!(resolve("zecrocks", crate::network::regtest()).is_err());
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
        apply_tls(
            &mut s,
            TlsOptions {
                force_tls: Some(true),
                ..Default::default()
            },
        );
        assert!(s.use_tls(), "tls = \"yes\" forces TLS on a local host");
        let mut s = resolve("http://203.0.113.5:9067", ZNetwork::Main).unwrap();
        apply_tls(
            &mut s,
            TlsOptions {
                force_tls: Some(true),
                ..Default::default()
            },
        );
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
    fn tls_insecure_skip_verify_is_off_unless_configured() {
        // A resolved endpoint verifies certificates; nothing about `https://` or the public
        // preset opts into the escape hatch.
        for token in [
            "https://lwd.example.com",
            "zecrocks",
            "lwd.example.com:9067",
        ] {
            let s = resolve(token, ZNetwork::Main).unwrap();
            assert!(s.use_tls());
            assert!(
                !s.tls.insecure_skip_verify,
                "{token} must verify certificates by default"
            );
        }
        // The config knob is what turns it on, and it is not sticky - a later apply with the
        // flag off restores verification.
        let mut s = resolve("https://lwd.example.com", ZNetwork::Main).unwrap();
        apply_tls(
            &mut s,
            TlsOptions {
                insecure_skip_verify: true,
                ..Default::default()
            },
        );
        assert!(s.tls.insecure_skip_verify);
        apply_tls(&mut s, TlsOptions::default());
        assert!(!s.tls.insecure_skip_verify);
    }

    #[test]
    fn cert_fingerprints_parse_openssl_output_and_round_trip() {
        // openssl prints colon-separated uppercase hex; bare lowercase hex is equally accepted,
        // and both parse to the same pin.
        let openssl = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
                       AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
        let bare = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let a = CertFingerprint::parse(openssl).unwrap();
        let b = CertFingerprint::parse(bare).unwrap();
        assert_eq!(a, b);
        // Display is openssl's own form, so a rejected fingerprint can be pasted back into the
        // config without reformatting.
        assert_eq!(a.to_string(), openssl.replace(['\\', ' ', '\n'], ""));
        assert_eq!(CertFingerprint::parse(&a.to_string()).unwrap(), a);
        // Wrong length (a SHA-1 fingerprint, the other thing openssl will happily print), and
        // non-hex, are rejected rather than silently truncated.
        assert!(CertFingerprint::parse("AB:CD:EF:01:23:45:67:89:AB:CD").is_err());
        assert!(CertFingerprint::parse(&"z".repeat(64)).is_err());
    }

    #[test]
    fn pinned_verifier_accepts_only_the_pinned_certificate() {
        // Nothing here parses as X.509 - the pin is a hash over the DER bytes, so any blob
        // stands in for a certificate.
        let cert = CertificateDer::from(vec![7u8; 32]);
        let other = CertificateDer::from(vec![8u8; 32]);
        let pin = CertFingerprint::of(&cert);
        let name = ServerName::try_from("lwd.example.com").unwrap();

        // Pin-only mode (no CA): the fingerprint is the whole identity.
        let verifier = PinnedServerCertVerification::new(
            vec![pin],
            None,
            rustls::crypto::ring::default_provider().into(),
        )
        .unwrap();
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .is_ok());

        // A different certificate is refused, and the error names the fingerprint actually
        // presented - the only way an operator can bootstrap or rotate a pin.
        let err = verifier
            .verify_server_cert(&other, &[], &name, &[], UnixTime::now())
            .expect_err("an unpinned certificate must be refused");
        assert!(
            err.to_string()
                .contains(&CertFingerprint::of(&other).to_string()),
            "error should quote the presented fingerprint: {err}"
        );

        // Several pins are accepted, so a replacement can be pinned before it is deployed.
        let multi = PinnedServerCertVerification::new(
            vec![CertFingerprint::of(&other), pin],
            None,
            rustls::crypto::ring::default_provider().into(),
        )
        .unwrap();
        for c in [&cert, &other] {
            assert!(multi
                .verify_server_cert(c, &[], &name, &[], UnixTime::now())
                .is_ok());
        }
    }

    #[test]
    fn tls_options_are_applied_and_the_scheme_still_wins() {
        let pin = CertFingerprint::parse(&"ab".repeat(32)).unwrap();
        let opts = TlsOptions {
            force_tls: Some(true),
            roots: TlsRoots::Webpki,
            insecure_skip_verify: false,
            ca_pem: Some(b"-----BEGIN CERTIFICATE-----".to_vec()),
            pins: vec![pin],
        };
        // A bare host:port takes the configured TLS mode…
        let mut s = resolve("lwd.example.com:9067", ZNetwork::Main).unwrap();
        apply_tls(&mut s, opts.clone());
        assert!(s.use_tls());
        assert_eq!(s.tls.roots, TlsRoots::Webpki);
        assert_eq!(s.tls.pins, vec![pin]);
        assert!(s.tls.ca_pem.is_some());
        assert!(s.tls.requires_tls());
        // …but an explicit scheme still wins over it, as for every other TLS setting.
        let mut s = resolve("http://127.0.0.1:9067", crate::network::regtest()).unwrap();
        apply_tls(&mut s, opts);
        assert!(!s.use_tls(), "http:// wins over tls = \"yes\"");
    }

    #[test]
    fn the_transparent_capability_override_only_applies_to_lightwalletd() {
        // A lightwalletd endpoint takes the assertion: the operator knows their 0.5.x server
        // serves transparent data even though it advertises no protocol version.
        let mut s = resolve("lwd.example.com:9067", ZNetwork::Main).unwrap();
        assert!(!s.assume_transparent_in_compact_blocks, "off by default");
        apply_transparent_capability_override(&mut s, true);
        assert!(s.assume_transparent_in_compact_blocks);
        // A zebra endpoint ignores it - its block scan always covers transparent data, so the
        // flag would be a never-consulted setting rather than a meaningful assertion.
        let mut s = resolve("zebra://127.0.0.1:18234", crate::network::regtest()).unwrap();
        apply_transparent_capability_override(&mut s, true);
        assert!(!s.assume_transparent_in_compact_blocks);
    }

    #[tokio::test]
    async fn pins_refuse_to_ride_a_plaintext_connection() {
        // The locality heuristic resolves a loopback endpoint to plaintext, where a pin can
        // never be checked. Connecting must fail loudly rather than silently ignore it.
        let mut s = resolve("127.0.0.1:9067", crate::network::regtest()).unwrap();
        apply_tls(
            &mut s,
            TlsOptions {
                pins: vec![CertFingerprint::parse(&"cd".repeat(32)).unwrap()],
                ..Default::default()
            },
        );
        assert!(!s.use_tls());
        let err = match s.connect_lwd().await {
            Ok(_) => panic!("a pinned plaintext endpoint must be refused"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("plaintext"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn insecure_verifier_accepts_any_certificate() {
        let verifier = NoServerCertVerification::new();
        // Not even a parseable certificate, presented under a name it could never be issued
        // for: the whole point is that neither is checked.
        let cert = CertificateDer::from(vec![0u8; 8]);
        let name = ServerName::try_from("lwd.example.com").unwrap();
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .is_ok());
        // Handshake signatures are still checked against the presented key, so the verifier
        // has to advertise the provider's schemes rather than an empty set.
        assert!(!verifier.supported_verify_schemes().is_empty());
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
        let server = resolve("zecrocks", ZNetwork::Test).unwrap();
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
        let server = resolve("zecrocks", ZNetwork::Test).unwrap();
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
        let server = resolve("zecrocks", ZNetwork::Main).unwrap();
        let mut source = server.connect().await.expect("connect to zec.rocks");
        let tip = source.latest_block().await.expect("latest block");
        assert!(tip.height > 2_500_000, "mainnet is past height 2.5M");
        assert_eq!(tip.hash.len(), 32);
    }
}
