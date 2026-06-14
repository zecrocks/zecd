//! Cloud-KMS keystore providers: envelope encryption of the wallet's at-rest age identity.
//!
//! A KMS-keystore wallet keeps its mnemonic in `keys.toml` age-encrypted to a dedicated
//! x25519 identity, and stores that identity *wrapped* (encrypted) by a key held in AWS KMS
//! or Google Cloud KMS. Unlocking is one IAM-gated `Decrypt` call at startup - the cloud
//! provider only ever sees the random wrap target, never the mnemonic or seed, and every
//! unlock is an attributable CloudTrail / Cloud Audit Logs entry. This is the same
//! "auto-unseal" pattern ops teams run for Vault/SOPS: disk/backup theft of `keys.toml`
//! alone is useless without the cloud credentials.
//!
//! Provider clients:
//! - AWS: `aws-sdk-kms` over the standard credential chain (env, profile, IMDS instance
//!   roles, ECS, IRSA web identity). The key may be an ARN (its region wins) or a key
//!   id/alias (region from the chain).
//! - GCP: the Cloud KMS REST API with `gcp_auth` Application Default Credentials (metadata
//!   server, `GOOGLE_APPLICATION_CREDENTIALS` service-account key, gcloud user creds). The
//!   `ZECD_GCP_ACCESS_TOKEN` env var bypasses ADC with a static bearer token - for tests
//!   and emulators only.
//!
//! Both providers honor an `endpoint` override (`[keystore] endpoint`), which is how the
//! offline tests run against in-process fake servers and how e2e runs target emulators
//! (moto/local-kms for AWS; community Cloud KMS emulators for GCP).

use anyhow::{anyhow, Context};
use secrecy::{ExposeSecret as _, SecretVec};

#[cfg(feature = "keystore")]
use {
    anyhow::bail,
    base64::Engine as _,
    bytes::Bytes,
    http_body_util::{BodyExt as _, Full},
    hyper_util::client::legacy::Client as HyperClient,
    hyper_util::rt::TokioExecutor,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
    std::time::Duration,
};

/// Total wall-clock budget for one KMS operation, covering credential resolution, TLS, and
/// SDK-internal retries. Unlock failures are retried by the wallet actor with backoff, so a
/// hung endpoint must not stall startup or the actor's command loop indefinitely.
#[cfg(feature = "keystore")]
const KMS_OP_TIMEOUT: Duration = Duration::from_secs(15);

/// OAuth scope required by the Cloud KMS encrypt/decrypt endpoints.
#[cfg(feature = "keystore")]
const GCP_KMS_SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";

/// Static bearer token override for GCP (skips ADC). Tests and emulators only - a real
/// deployment should let Application Default Credentials supply short-lived tokens.
pub const GCP_TOKEN_ENV: &str = "ZECD_GCP_ACCESS_TOKEN";

#[cfg(feature = "keystore")]
const GCP_DEFAULT_ENDPOINT: &str = "https://cloudkms.googleapis.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreProvider {
    AwsKms,
    GcpKms,
}

impl KeystoreProvider {
    pub fn parse(s: &str) -> anyhow::Result<KeystoreProvider> {
        match s.trim().to_ascii_lowercase().as_str() {
            "aws-kms" | "aws" => Ok(KeystoreProvider::AwsKms),
            "gcp-kms" | "gcp" => Ok(KeystoreProvider::GcpKms),
            other => Err(anyhow!(
                "unknown keystore provider {other:?} (expected \"aws-kms\" or \"gcp-kms\")"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            KeystoreProvider::AwsKms => "aws-kms",
            KeystoreProvider::GcpKms => "gcp-kms",
        }
    }
}

/// Values cryptographically bound to the wrapped identity as AWS encryption context / GCP
/// additional authenticated data. Decryption must present the same values, and (for AWS)
/// they ride on every CloudTrail entry, so each unlock is attributable to a wallet. The
/// wallet label is fixed at wrap time and stored in `keys.toml` (rename-safe); none of this
/// is secret.
#[derive(Debug, Clone)]
pub struct WrapContext {
    pub wallet: String,
    pub network: String,
}

#[cfg(feature = "keystore")]
impl WrapContext {
    fn aws_context(&self) -> HashMap<String, String> {
        HashMap::from([
            ("zecd:wallet".to_string(), self.wallet.clone()),
            ("zecd:network".to_string(), self.network.clone()),
        ])
    }

    fn gcp_aad(&self) -> Vec<u8> {
        format!("zecd:wallet={};network={}", self.wallet, self.network).into_bytes()
    }
}

/// One configured KMS key, ready to wrap/unwrap. Built either from `[keystore]` config
/// (init/rewrap) or from a wallet's `keys.toml` KMS metadata (unlock).
#[derive(Debug, Clone)]
pub struct Keystore {
    pub provider: KeystoreProvider,
    /// AWS: key ARN (preferred - its region wins), bare key id, or `alias/...`.
    /// GCP: full resource name `projects/.../locations/.../keyRings/.../cryptoKeys/...`.
    pub key: String,
    /// API endpoint override (emulators, VPC/private endpoints); `None` = provider default.
    pub endpoint: Option<String>,
}

#[cfg(feature = "keystore")]
impl Keystore {
    /// Encrypt `plaintext` under the KMS key, binding `ctx`. Returns the opaque ciphertext
    /// blob to store in `keys.toml`.
    pub async fn wrap(&self, plaintext: &[u8], ctx: &WrapContext) -> anyhow::Result<Vec<u8>> {
        let op = async {
            match self.provider {
                KeystoreProvider::AwsKms => self.aws_wrap(plaintext, ctx).await,
                KeystoreProvider::GcpKms => self.gcp_wrap(plaintext, ctx).await,
            }
        };
        tokio::time::timeout(KMS_OP_TIMEOUT, op)
            .await
            .map_err(|_| {
                anyhow!(
                    "{} encrypt timed out after {KMS_OP_TIMEOUT:?}",
                    self.provider.name()
                )
            })?
    }

    /// Decrypt a blob produced by [`Keystore::wrap`] with the same `ctx`.
    pub async fn unwrap(
        &self,
        ciphertext: &[u8],
        ctx: &WrapContext,
    ) -> anyhow::Result<SecretVec<u8>> {
        let op = async {
            match self.provider {
                KeystoreProvider::AwsKms => self.aws_unwrap(ciphertext, ctx).await,
                KeystoreProvider::GcpKms => self.gcp_unwrap(ciphertext, ctx).await,
            }
        };
        tokio::time::timeout(KMS_OP_TIMEOUT, op)
            .await
            .map_err(|_| {
                anyhow!(
                    "{} decrypt timed out after {KMS_OP_TIMEOUT:?}",
                    self.provider.name()
                )
            })?
    }

    // --- AWS ---------------------------------------------------------------

    async fn aws_client(&self) -> aws_sdk_kms::Client {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = arn_region(&self.key) {
            loader = loader.region(aws_config::Region::new(region));
        }
        if let Some(endpoint) = &self.endpoint {
            loader = loader.endpoint_url(endpoint);
        }
        aws_sdk_kms::Client::new(&loader.load().await)
    }

    async fn aws_wrap(&self, plaintext: &[u8], ctx: &WrapContext) -> anyhow::Result<Vec<u8>> {
        let out = self
            .aws_client()
            .await
            .encrypt()
            .key_id(&self.key)
            .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
            .set_encryption_context(Some(ctx.aws_context()))
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "aws-kms Encrypt: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                )
            })?;
        Ok(out
            .ciphertext_blob()
            .ok_or_else(|| anyhow!("aws-kms Encrypt returned no ciphertext"))?
            .as_ref()
            .to_vec())
    }

    async fn aws_unwrap(
        &self,
        ciphertext: &[u8],
        ctx: &WrapContext,
    ) -> anyhow::Result<SecretVec<u8>> {
        let out = self
            .aws_client()
            .await
            .decrypt()
            // Pinning the key id makes a swapped-in ciphertext from another key fail loudly.
            .key_id(&self.key)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
            .set_encryption_context(Some(ctx.aws_context()))
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "aws-kms Decrypt: {}",
                    aws_sdk_kms::error::DisplayErrorContext(e)
                )
            })?;
        Ok(SecretVec::new(
            out.plaintext()
                .ok_or_else(|| anyhow!("aws-kms Decrypt returned no plaintext"))?
                .as_ref()
                .to_vec(),
        ))
    }

    // --- GCP ---------------------------------------------------------------

    async fn gcp_wrap(&self, plaintext: &[u8], ctx: &WrapContext) -> anyhow::Result<Vec<u8>> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let req = GcpEncryptRequest {
            plaintext: b64.encode(plaintext),
            additional_authenticated_data: b64.encode(ctx.gcp_aad()),
        };
        let resp: GcpEncryptResponse = self.gcp_post("encrypt", &req).await?;
        b64.decode(resp.ciphertext.as_deref().unwrap_or_default())
            .context("gcp-kms encrypt returned invalid base64 ciphertext")
    }

    async fn gcp_unwrap(
        &self,
        ciphertext: &[u8],
        ctx: &WrapContext,
    ) -> anyhow::Result<SecretVec<u8>> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let req = GcpDecryptRequest {
            ciphertext: b64.encode(ciphertext),
            additional_authenticated_data: b64.encode(ctx.gcp_aad()),
        };
        let resp: GcpDecryptResponse = self.gcp_post("decrypt", &req).await?;
        Ok(SecretVec::new(
            b64.decode(resp.plaintext.as_deref().unwrap_or_default())
                .context("gcp-kms decrypt returned invalid base64 plaintext")?,
        ))
    }

    /// POST one Cloud KMS action (`{endpoint}/v1/{key}:{action}`) as JSON with a bearer token.
    async fn gcp_post<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        req: &Req,
    ) -> anyhow::Result<Resp> {
        if !self.key.starts_with("projects/") || !self.key.contains("/cryptoKeys/") {
            bail!(
                "gcp-kms key must be a full resource name \
                 (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>), got {:?}",
                self.key
            );
        }
        let base = self.endpoint.as_deref().unwrap_or(GCP_DEFAULT_ENDPOINT);
        let uri: hyper::Uri = format!("{}/v1/{}:{action}", base.trim_end_matches('/'), self.key)
            .parse()
            .context("building gcp-kms request URI")?;
        let token = gcp_token().await?;

        // Plain HTTP is accepted so emulators work; the real endpoint default is HTTPS. The
        // explicit ring provider avoids the rustls multi-provider ambiguity panic (both ring
        // - via tonic - and aws-lc-rs - via the AWS SDK - are compiled in).
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls::crypto::ring::default_provider())
            .context("loading native TLS roots")?
            .https_or_http()
            .enable_http1()
            .build();
        let client: HyperClient<_, Full<Bytes>> =
            HyperClient::builder(TokioExecutor::new()).build(connector);

        let request = hyper::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Full::new(Bytes::from(serde_json::to_vec(req)?)))?;
        let response = client
            .request(request)
            .await
            .map_err(|e| anyhow!("gcp-kms {action} request failed: {e}"))?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow!("gcp-kms {action} reading response: {e}"))?
            .to_bytes();
        if !status.is_success() {
            bail!(
                "gcp-kms {action} failed: HTTP {status}: {}",
                String::from_utf8_lossy(&body[..body.len().min(512)])
            );
        }
        serde_json::from_slice(&body).context("parsing gcp-kms response")
    }
}

/// Without the `keystore` cargo feature the keystore *types* still exist - `[keystore]`
/// config and KMS-marked `keys.toml` files parse, and a KMS wallet opens read-only - but
/// every cloud operation reports that support isn't compiled in.
#[cfg(not(feature = "keystore"))]
impl Keystore {
    pub async fn wrap(&self, _plaintext: &[u8], _ctx: &WrapContext) -> anyhow::Result<Vec<u8>> {
        Err(self.unsupported())
    }

    pub async fn unwrap(
        &self,
        _ciphertext: &[u8],
        _ctx: &WrapContext,
    ) -> anyhow::Result<SecretVec<u8>> {
        Err(self.unsupported())
    }

    fn unsupported(&self) -> anyhow::Error {
        anyhow!(
            "{} support is not compiled into this binary (built without the `keystore` cargo \
             feature); rebuild zecd with default features to use a cloud keystore",
            self.provider.name()
        )
    }
}

/// Resolve a GCP bearer token: the test/emulator env override, else Application Default
/// Credentials via `gcp_auth`.
#[cfg(feature = "keystore")]
async fn gcp_token() -> anyhow::Result<String> {
    if let Ok(token) = std::env::var(GCP_TOKEN_ENV) {
        if !token.is_empty() {
            return Ok(token);
        }
    }
    let provider = gcp_auth::provider()
        .await
        .context("resolving GCP credentials (Application Default Credentials)")?;
    let token = provider
        .token(&[GCP_KMS_SCOPE])
        .await
        .context("fetching GCP access token")?;
    Ok(token.as_str().to_string())
}

/// Region segment of a KMS key ARN (`arn:aws:kms:<region>:...`); `None` for ids/aliases,
/// which defer to the SDK's region chain (`AWS_REGION`, profile, IMDS).
#[cfg(feature = "keystore")]
fn arn_region(key: &str) -> Option<String> {
    let mut parts = key.split(':');
    (parts.next()? == "arn").then_some(())?;
    parts.next()?; // partition
    (parts.next()? == "kms").then_some(())?;
    let region = parts.next()?;
    (!region.is_empty()).then(|| region.to_string())
}

#[cfg(feature = "keystore")]
#[derive(Serialize)]
struct GcpEncryptRequest {
    plaintext: String,
    #[serde(rename = "additionalAuthenticatedData")]
    additional_authenticated_data: String,
}

#[cfg(feature = "keystore")]
#[derive(Deserialize)]
struct GcpEncryptResponse {
    ciphertext: Option<String>,
}

#[cfg(feature = "keystore")]
#[derive(Serialize)]
struct GcpDecryptRequest {
    ciphertext: String,
    #[serde(rename = "additionalAuthenticatedData")]
    additional_authenticated_data: String,
}

#[cfg(feature = "keystore")]
#[derive(Deserialize)]
struct GcpDecryptResponse {
    plaintext: Option<String>,
}

/// Unwrap a KMS-wrapped age x25519 identity back to a usable identity. The wrapped bytes
/// are the identity's Bech32 encoding (`AGE-SECRET-KEY-1...`).
pub async fn unwrap_identity(
    keystore: &Keystore,
    wrapped: &[u8],
    ctx: &WrapContext,
) -> anyhow::Result<age::x25519::Identity> {
    let bytes = keystore.unwrap(wrapped, ctx).await?;
    let s = std::str::from_utf8(bytes.expose_secret())
        .context("unwrapped age identity is not valid UTF-8")?;
    s.trim()
        .parse::<age::x25519::Identity>()
        .map_err(|e| anyhow!("parsing unwrapped age identity: {e}"))
}

// ---------------------------------------------------------------------------
// In-process fake KMS servers (offline tests)
// ---------------------------------------------------------------------------

/// Test doubles for both KMS APIs, faithful enough to exercise the real SDK/HTTP clients:
/// the AWS fake speaks the `x-amz-json-1.1` protocol `aws-sdk-kms` emits, the GCP fake the
/// REST shapes above. "Ciphertext" is a transparent JSON envelope (key id + context +
/// plaintext) so decrypt can verify key pinning and context binding - mismatches return the
/// provider's real error shape. Public (not `#[cfg(test)]`) so `tests/cli.rs` can run the
/// compiled binary against them; they are compiled into test builds only via dev-deps usage.
#[cfg(feature = "keystore")]
pub mod fake {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::extract::{Path, State};
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use base64::Engine as _;

    /// The reversible "ciphertext" payload both fakes use.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct FakeBlob {
        key: String,
        context: std::collections::BTreeMap<String, String>,
        plaintext_b64: String,
    }

    fn seal(key: &str, context: std::collections::BTreeMap<String, String>, pt: &[u8]) -> String {
        let blob = FakeBlob {
            key: key.to_string(),
            context,
            plaintext_b64: base64::engine::general_purpose::STANDARD.encode(pt),
        };
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&blob).unwrap())
    }

    fn open(b64: &str) -> Option<FakeBlob> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Spawn a fake AWS KMS endpoint serving one key id. Returns its base URL.
    pub async fn spawn_aws(key_arn: &str) -> String {
        #[derive(Clone)]
        struct Fake {
            key: Arc<String>,
        }

        async fn handler(
            State(fake): State<Fake>,
            headers: HeaderMap,
            // Raw bytes: the SDK posts `application/x-amz-json-1.1`, which axum's `Json`
            // extractor would reject with 415.
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            let body: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => return axum::http::StatusCode::BAD_REQUEST.into_response(),
            };
            let target = headers
                .get("x-amz-target")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let ctx: std::collections::BTreeMap<String, String> = body
                .get("EncryptionContext")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let err = |code: &str, msg: &str| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    [("content-type", "application/x-amz-json-1.1")],
                    serde_json::json!({"__type": code, "message": msg}).to_string(),
                )
                    .into_response()
            };
            match target.as_str() {
                "TrentService.Encrypt" => {
                    let key = body
                        .get("KeyId")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if key != fake.key.as_str() {
                        return err("NotFoundException", "unknown key");
                    }
                    let pt = body
                        .get("Plaintext")
                        .and_then(|v| v.as_str())
                        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                        .unwrap_or_default();
                    (
                        [("content-type", "application/x-amz-json-1.1")],
                        serde_json::json!({
                            "CiphertextBlob": seal(key, ctx, &pt),
                            "KeyId": key,
                        })
                        .to_string(),
                    )
                        .into_response()
                }
                "TrentService.Decrypt" => {
                    let Some(blob) = body
                        .get("CiphertextBlob")
                        .and_then(|v| v.as_str())
                        .and_then(open)
                    else {
                        return err("InvalidCiphertextException", "malformed ciphertext");
                    };
                    if blob.key != *fake.key || blob.context != ctx {
                        return err(
                            "InvalidCiphertextException",
                            "key or encryption context mismatch",
                        );
                    }
                    (
                        [("content-type", "application/x-amz-json-1.1")],
                        serde_json::json!({
                            "Plaintext": blob.plaintext_b64,
                            "KeyId": blob.key,
                        })
                        .to_string(),
                    )
                        .into_response()
                }
                other => err("UnknownOperationException", other),
            }
        }

        let fake = Fake {
            key: Arc::new(key_arn.to_string()),
        };
        let app = Router::new().route("/", post(handler)).with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Spawn a fake GCP Cloud KMS endpoint serving one crypto-key resource. Returns its
    /// base URL.
    pub async fn spawn_gcp(key_resource: &str) -> String {
        #[derive(Clone)]
        struct Fake {
            key: Arc<String>,
        }

        async fn handler(
            State(fake): State<Fake>,
            Path(rest): Path<String>,
            Json(body): Json<HashMap<String, String>>,
        ) -> axum::response::Response {
            let err = |status: axum::http::StatusCode, msg: &str| {
                (
                    status,
                    Json(serde_json::json!({"error": {"code": status.as_u16(), "message": msg}})),
                )
                    .into_response()
            };
            let Some((key, action)) = rest.rsplit_once(':') else {
                return err(axum::http::StatusCode::NOT_FOUND, "no action");
            };
            if key != fake.key.as_str() {
                return err(axum::http::StatusCode::NOT_FOUND, "unknown crypto key");
            }
            // The fake folds the AAD into the seal's context map for the same
            // mismatch-detection the AWS fake does.
            let ctx = std::collections::BTreeMap::from([(
                "aad".to_string(),
                body.get("additionalAuthenticatedData")
                    .cloned()
                    .unwrap_or_default(),
            )]);
            match action {
                "encrypt" => {
                    let pt = body
                        .get("plaintext")
                        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                        .unwrap_or_default();
                    Json(serde_json::json!({
                        "name": key,
                        "ciphertext": seal(key, ctx, &pt),
                    }))
                    .into_response()
                }
                "decrypt" => {
                    // The request's `ciphertext` field is base64 of the raw bytes the client
                    // got back from encrypt - which, for this fake, are the blob JSON itself
                    // (the encrypt response's base64 was the API encoding, not the payload).
                    let Some(blob) = body
                        .get("ciphertext")
                        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                        .and_then(|raw| serde_json::from_slice::<FakeBlob>(&raw).ok())
                    else {
                        return err(axum::http::StatusCode::BAD_REQUEST, "malformed ciphertext");
                    };
                    if blob.key != *fake.key || blob.context != ctx {
                        return err(
                            axum::http::StatusCode::BAD_REQUEST,
                            "decryption failed: ciphertext/AAD mismatch",
                        );
                    }
                    Json(serde_json::json!({"plaintext": blob.plaintext_b64})).into_response()
                }
                other => err(axum::http::StatusCode::NOT_FOUND, other),
            }
        }

        let fake = Fake {
            key: Arc::new(key_resource.to_string()),
        };
        let app = Router::new()
            .route("/v1/*rest", post(handler))
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    /// Set the env credentials both providers' clients need to talk to the fakes (static
    /// AWS creds so the SDK's chain resolves without IMDS, and the GCP bearer override).
    pub fn set_fake_credentials() {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
        std::env::set_var(super::GCP_TOKEN_ENV, "fake-test-token");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parses_and_rejects() {
        assert_eq!(
            KeystoreProvider::parse("aws-kms").unwrap(),
            KeystoreProvider::AwsKms
        );
        assert_eq!(
            KeystoreProvider::parse(" GCP ").unwrap(),
            KeystoreProvider::GcpKms
        );
        assert!(KeystoreProvider::parse("vault").is_err());
    }
}

/// Provider round-trips against the in-process fake KMS servers (feature-gated with the
/// providers themselves).
#[cfg(all(test, feature = "keystore"))]
mod provider_tests {
    use super::*;

    const AWS_KEY: &str = "arn:aws:kms:us-east-1:111122223333:key/test-key-id";
    const GCP_KEY: &str = "projects/p/locations/global/keyRings/r/cryptoKeys/k";

    fn ctx() -> WrapContext {
        WrapContext {
            wallet: "default".to_string(),
            network: "regtest".to_string(),
        }
    }

    fn keystore(provider: KeystoreProvider, key: &str, endpoint: String) -> Keystore {
        Keystore {
            provider,
            key: key.to_string(),
            endpoint: Some(endpoint),
        }
    }

    #[test]
    fn arn_region_extraction() {
        assert_eq!(arn_region(AWS_KEY).as_deref(), Some("us-east-1"));
        assert_eq!(arn_region("alias/zecd"), None);
        assert_eq!(arn_region("1234abcd-key-id"), None);
    }

    // The AWS SDK spawns its own connector machinery; multi-thread runtime matches the
    // daemon's environment.
    #[tokio::test(flavor = "multi_thread")]
    async fn aws_wrap_unwrap_roundtrip_and_context_binding() {
        fake::set_fake_credentials();
        let endpoint = fake::spawn_aws(AWS_KEY).await;
        let ks = keystore(KeystoreProvider::AwsKms, AWS_KEY, endpoint);

        let wrapped = ks.wrap(b"AGE-SECRET-KEY-1EXAMPLE", &ctx()).await.unwrap();
        assert_ne!(wrapped, b"AGE-SECRET-KEY-1EXAMPLE");
        let back = ks.unwrap(&wrapped, &ctx()).await.unwrap();
        assert_eq!(back.expose_secret().as_slice(), b"AGE-SECRET-KEY-1EXAMPLE");

        // A different encryption context must fail (the audit/binding invariant).
        let other = WrapContext {
            wallet: "other".to_string(),
            network: "regtest".to_string(),
        };
        let err = ks
            .unwrap(&wrapped, &other)
            .await
            .err()
            .expect("context mismatch must fail")
            .to_string();
        assert!(err.contains("InvalidCiphertext"), "got: {err}");

        // Tampered ciphertext must fail.
        assert!(ks.unwrap(b"garbage", &ctx()).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn aws_wrong_key_is_refused() {
        fake::set_fake_credentials();
        let endpoint = fake::spawn_aws(AWS_KEY).await;
        let ks = keystore(
            KeystoreProvider::AwsKms,
            "arn:aws:kms:us-east-1:111122223333:key/other-key",
            endpoint,
        );
        assert!(ks.wrap(b"x", &ctx()).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gcp_wrap_unwrap_roundtrip_and_aad_binding() {
        fake::set_fake_credentials();
        let endpoint = fake::spawn_gcp(GCP_KEY).await;
        let ks = keystore(KeystoreProvider::GcpKms, GCP_KEY, endpoint);

        let wrapped = ks.wrap(b"AGE-SECRET-KEY-1EXAMPLE", &ctx()).await.unwrap();
        let back = ks.unwrap(&wrapped, &ctx()).await.unwrap();
        assert_eq!(back.expose_secret().as_slice(), b"AGE-SECRET-KEY-1EXAMPLE");

        let other = WrapContext {
            wallet: "other".to_string(),
            network: "regtest".to_string(),
        };
        let err = ks
            .unwrap(&wrapped, &other)
            .await
            .err()
            .expect("AAD mismatch must fail")
            .to_string();
        assert!(
            err.contains("mismatch") || err.contains("400"),
            "got: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gcp_requires_full_resource_name() {
        fake::set_fake_credentials();
        let ks = keystore(
            KeystoreProvider::GcpKms,
            "my-key",
            "http://127.0.0.1:1".to_string(),
        );
        let err = ks.wrap(b"x", &ctx()).await.unwrap_err().to_string();
        assert!(err.contains("full resource name"), "got: {err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unwrap_identity_roundtrip() {
        fake::set_fake_credentials();
        let endpoint = fake::spawn_aws(AWS_KEY).await;
        let ks = keystore(KeystoreProvider::AwsKms, AWS_KEY, endpoint);

        let identity = age::x25519::Identity::generate();
        let identity_str = {
            use age::secrecy::ExposeSecret as _;
            let secret = identity.to_string();
            secret.expose_secret().to_owned()
        };
        let wrapped = ks.wrap(identity_str.as_bytes(), &ctx()).await.unwrap();
        let back = unwrap_identity(&ks, &wrapped, &ctx()).await.unwrap();
        assert_eq!(
            back.to_public().to_string(),
            identity.to_public().to_string()
        );
    }
}
