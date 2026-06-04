//! HTTP Basic authentication, compatible with Bitcoin Core's `rpcuser`/`rpcpassword`
//! and its `.cookie` file scheme.

use std::path::Path;

use anyhow::{anyhow, Context};
use base64::Engine;
use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::config::RpcConfig;

/// Holds the single expected credential pair and checks incoming `Authorization` headers.
#[derive(Clone)]
pub struct Authenticator {
    user: String,
    password: String,
}

impl Authenticator {
    /// Build from config. If `rpcuser`/`rpcpassword` are set, that pair is required.
    /// Otherwise a bitcoind-style cookie (`__cookie__:<random>`) is generated and written
    /// to the cookie file (mode 0600 on Unix).
    pub fn from_config(rpc: &RpcConfig) -> anyhow::Result<Authenticator> {
        if let (Some(user), Some(password)) = (&rpc.user, &rpc.password) {
            return Ok(Authenticator {
                user: user.clone(),
                password: password.clone(),
            });
        }

        let cookiefile = rpc.cookiefile.as_ref().ok_or_else(|| {
            anyhow!("no RPC auth configured: set [rpc] user+password or a cookiefile")
        })?;

        let password = random_hex(32);
        write_cookie(cookiefile, "__cookie__", &password)
            .with_context(|| format!("writing cookie file {}", cookiefile.display()))?;
        Ok(Authenticator {
            user: "__cookie__".to_string(),
            password,
        })
    }

    /// Verify an `Authorization` header value (e.g. `Basic dXNlcjpwYXNz`).
    pub fn check(&self, header: Option<&str>) -> bool {
        let Some(header) = header else { return false };
        let Some(b64) = header.strip_prefix("Basic ").or_else(|| header.strip_prefix("basic ")) else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            return false;
        };
        let Ok(creds) = std::str::from_utf8(&decoded) else { return false };
        let Some((user, password)) = creds.split_once(':') else { return false };

        let user_ok = user.as_bytes().ct_eq(self.user.as_bytes());
        let pass_ok = password.as_bytes().ct_eq(self.password.as_bytes());
        (user_ok & pass_ok).into()
    }
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn write_cookie(path: &Path, user: &str, password: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = format!("{user}:{password}");
    std::fs::write(path, contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(user: &str, pass: &str) -> String {
        let raw = format!("{user}:{pass}");
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
        )
    }

    #[test]
    fn accepts_correct_rejects_wrong() {
        let auth = Authenticator {
            user: "alice".into(),
            password: "secret".into(),
        };
        assert!(auth.check(Some(&basic("alice", "secret"))));
        assert!(!auth.check(Some(&basic("alice", "wrong"))));
        assert!(!auth.check(Some(&basic("bob", "secret"))));
        assert!(!auth.check(None));
        assert!(!auth.check(Some("Bearer xyz")));
    }
}
