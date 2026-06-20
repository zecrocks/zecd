//! HTTP Basic authentication, compatible with Bitcoin Core's `rpcauth` multi-user list,
//! `rpcuser`/`rpcpassword`, and its `.cookie` file scheme.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

use crate::config::RpcConfig;

/// A salted password hash in Bitcoin Core's `rpcauth` format: `<salt>$<hex>` where the
/// hex digest is `HMAC-SHA256(key = salt, msg = password)`, as produced by bitcoind's
/// `share/rpcauth/rpcauth.py` (the scheme from bitcoin/bitcoin#7044).
#[derive(Clone)]
pub struct PasswordHash {
    salt: String,
    hash: [u8; 32],
}

/// Generate a bitcoind-style `rpcauth` credential line for `username` under a fresh random
/// salt, mirroring bitcoin's `share/rpcauth/rpcauth.py` (so operators need no external tool).
/// Returns `(line, generated_password)`: `line` is the `<user>:<salt>$<hmac-sha256 hex>` value
/// to drop into `[rpc] auth`; `generated_password` is `Some` only when `password` was `None`
/// and a random one was minted, so the caller can show the operator the secret to keep.
pub fn generate_rpcauth(username: &str, password: Option<&str>) -> (String, Option<String>) {
    let salt = random_hex(16);
    let (password, generated) = match password {
        Some(p) => (p.to_string(), None),
        None => {
            // 32 random bytes, URL-safe base64 - the same shape rpcauth.py mints.
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            let p = base64::engine::general_purpose::URL_SAFE.encode(buf);
            (p.clone(), Some(p))
        }
    };
    let hash = PasswordHash::compute(&password, &salt);
    let line = format!("{username}:{salt}${}", hex::encode(hash));
    (line, generated)
}

/// `zecd rpcauth <user> [password]`: print a salted credential line for `[rpc] auth`, plus the
/// password to keep when one is generated. No daemon, config, or external script needed.
pub fn run_rpcauth(args: &crate::config::RpcauthArgs) -> anyhow::Result<()> {
    let (line, generated) = generate_rpcauth(&args.username, args.password.as_deref());

    println!("Add this line to your zecd config under [rpc]:");
    println!();
    println!("auth = [\"{line}\"]");
    println!();
    if let Some(password) = generated {
        println!("Your RPC password (store it now - it is not recoverable):");
        println!();
        println!("{password}");
        println!();
    }
    Ok(())
}

impl PasswordHash {
    fn compute(password: &str, salt: &str) -> [u8; 32] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(salt.as_bytes()).expect("HMAC accepts any key length");
        mac.update(password.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Hash a bare password under a fresh random salt. Plain `rpcuser`/`rpcpassword` and
    /// cookie credentials are converted through this at startup so verification has a
    /// single path and no plaintext is retained.
    fn from_bare(password: &str) -> Self {
        let salt = random_hex(16);
        let hash = Self::compute(password, &salt);
        PasswordHash { salt, hash }
    }

    /// Constant-time password check returning a `subtle::Choice` so callers can combine it
    /// without short-circuiting. The HMAC is always computed, regardless of the result.
    fn check_ct(&self, password: &str) -> Choice {
        Self::compute(password, &self.salt).ct_eq(&self.hash)
    }

    #[cfg(test)]
    fn check(&self, password: &str) -> bool {
        self.check_ct(password).into()
    }
}

impl FromStr for PasswordHash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (salt, hash_hex) = s
            .split_once('$')
            .ok_or_else(|| anyhow!("expected <salt>$<hmac-sha256 hex>"))?;
        let mut hash = [0u8; 32];
        hex::decode_to_slice(hash_hex, &mut hash)
            .map_err(|_| anyhow!("hash is not 64 hex characters"))?;
        Ok(PasswordHash {
            salt: salt.to_string(),
            hash,
        })
    }
}

impl fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}${}", self.salt, hex::encode(self.hash))
    }
}

/// Holds the accepted credentials and checks incoming `Authorization` headers.
#[derive(Clone)]
pub struct Authenticator {
    users: Vec<(String, PasswordHash)>,
}

impl Authenticator {
    /// Build from config. Accepted credentials are the union of every `[rpc] auth`
    /// (`rpcauth`) entry and the `rpcuser`/`rpcpassword` pair; when no pair is set, a
    /// bitcoind-style cookie (`__cookie__:<random>`) is generated and written to the
    /// cookie file (mode 0600 on Unix) - also alongside `rpcauth` entries, as bitcoind
    /// does whenever `rpcpassword` is empty.
    pub fn from_config(rpc: &RpcConfig) -> anyhow::Result<Authenticator> {
        let mut users = Vec::new();

        for entry in &rpc.auth {
            let (user, pwhash) = entry
                .split_once(':')
                .ok_or_else(|| anyhow!("invalid rpcauth entry (expected user:salt$hash)"))?;
            let pwhash = pwhash
                .parse()
                .with_context(|| format!("invalid rpcauth entry for user {user}"))?;
            users.push((user.to_string(), pwhash));
        }

        if let (Some(user), Some(password)) = (&rpc.user, &rpc.password) {
            users.push((user.clone(), PasswordHash::from_bare(password)));
        } else {
            let cookiefile = rpc.cookiefile.as_ref().ok_or_else(|| {
                anyhow!("no RPC auth configured: set [rpc] user+password, auth, or a cookiefile")
            })?;

            let password = random_hex(32);
            write_cookie(cookiefile, "__cookie__", &password)
                .with_context(|| format!("writing cookie file {}", cookiefile.display()))?;
            users.push(("__cookie__".to_string(), PasswordHash::from_bare(&password)));
        }

        Ok(Authenticator { users })
    }

    /// Verify an `Authorization` header value (e.g. `Basic dXNlcjpwYXNz`).
    pub fn check(&self, header: Option<&str>) -> bool {
        let Some(header) = header else { return false };
        let Some(b64) = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
        else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
            return false;
        };
        let Ok(creds) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((user, password)) = creds.split_once(':') else {
            return false;
        };

        // Check every configured credential without short-circuiting: always run the password
        // HMAC (via `check_ct`) and combine with bitwise `Choice` ops, so response timing does
        // not reveal whether a username exists. (Username *length* can still differ; usernames
        // are not secret in bitcoind's model - the cookie user is the fixed `__cookie__`.)
        let mut found = Choice::from(0u8);
        for (u, hash) in &self.users {
            let user_ok = u.as_bytes().ct_eq(user.as_bytes());
            let pass_ok = hash.check_ct(password);
            found |= user_ok & pass_ok;
        }
        found.into()
    }
}

/// Recover the claimed username from a Basic `Authorization` header, for log attribution.
/// Returns `None` when the header is absent or not well-formed Basic auth. This performs **no**
/// credential verification - it only parses out the username so an auth success/failure can name
/// who attempted it. (The password is never returned or logged.)
pub fn basic_auth_username(header: Option<&str>) -> Option<String> {
    let header = header?;
    let b64 = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let creds = std::str::from_utf8(&decoded).ok()?;
    let (user, _password) = creds.split_once(':')?;
    Some(user.to_string())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn write_cookie(path: &Path, user: &str, password: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = format!("{user}:{password}");

    // Create the file with mode 0600 atomically (via OpenOptions) rather than writing then
    // chmod-ing, so the cookie is never briefly world-readable between create and set_permissions.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(contents.as_bytes())?;
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

    fn plain(user: &str, pass: &str) -> Authenticator {
        Authenticator {
            users: vec![(user.to_string(), PasswordHash::from_bare(pass))],
        }
    }

    #[test]
    fn accepts_correct_rejects_wrong() {
        let auth = plain("alice", "secret");
        assert!(auth.check(Some(&basic("alice", "secret"))));
        assert!(!auth.check(Some(&basic("alice", "wrong"))));
        assert!(!auth.check(Some(&basic("bob", "secret"))));
        assert!(!auth.check(None));
        assert!(!auth.check(Some("Bearer xyz")));
    }

    #[test]
    fn pwhash_round_trip() {
        let password = "abadpassword";
        let pwhash = PasswordHash::from_bare(password);
        assert!(pwhash.check(password));
        assert!(!pwhash.check("notthepassword"));

        let parsed: PasswordHash = pwhash.to_string().parse().unwrap();
        assert!(parsed.check(password));
    }

    /// Vector generated with bitcoind's `share/rpcauth/rpcauth.py` algorithm:
    /// `hmac.new(salt, password, 'SHA256').hexdigest()` for password "zecd-test-password".
    #[test]
    fn rpcauth_known_vector() {
        let cfg_entry = "alice:cb77f0957de88ff388cf817ddbc7273$d8e868390e30794e252adc9160b8656e206598d0bb67dad0c4a6b379ad0e4dac";
        let (user, pwhash) = cfg_entry.split_once(':').unwrap();
        let pwhash: PasswordHash = pwhash.parse().unwrap();
        assert_eq!(user, "alice");
        assert!(pwhash.check("zecd-test-password"));
        assert!(!pwhash.check("wrong-password"));
    }

    #[test]
    fn generated_rpcauth_round_trips() {
        // Explicit password: no secret is minted, and the line parses + verifies.
        let (line, generated) = generate_rpcauth("alice", Some("hunter2"));
        assert!(generated.is_none());
        let (user, pwhash) = line.split_once(':').unwrap();
        assert_eq!(user, "alice");
        let pwhash: PasswordHash = pwhash.parse().unwrap();
        assert!(pwhash.check("hunter2"));
        assert!(!pwhash.check("wrong"));

        // Generated password: the minted secret verifies against the line, and an
        // Authenticator built from the entry accepts it over the full Basic-auth path.
        let (line, generated) = generate_rpcauth("bob", None);
        let password = generated.expect("a password is minted when none is supplied");
        let (user, pwhash) = line.split_once(':').unwrap();
        assert_eq!(user, "bob");
        assert!(pwhash.parse::<PasswordHash>().unwrap().check(&password));

        let auth = Authenticator {
            users: vec![(user.to_string(), pwhash.parse().unwrap())],
        };
        assert!(auth.check(Some(&basic("bob", &password))));
        assert!(!auth.check(Some(&basic("bob", "nope"))));
    }

    #[test]
    fn malformed_rpcauth_entries_are_rejected() {
        for s in [
            "",
            "nodollar",
            "salt$shorthex",
            "salt$zz77f0957de88ff388cf817ddbc7273d8e868390e30794e252adc9160b8656e",
        ] {
            assert!(
                s.parse::<PasswordHash>().is_err(),
                "expected {s:?} to be rejected"
            );
        }
    }

    #[test]
    fn from_config_unions_rpcauth_pair_and_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let cookie = dir.path().join(".cookie");
        let rpc = crate::config::RpcConfig {
            bind: "127.0.0.1".parse().unwrap(),
            port: 1,
            user: None,
            password: None,
            auth: vec![
                "alice:cb77f0957de88ff388cf817ddbc7273$d8e868390e30794e252adc9160b8656e206598d0bb67dad0c4a6b379ad0e4dac".to_string(),
            ],
            cookiefile: Some(cookie.clone()),
            work_queue: 16,
            allowed_methods: vec![],
        };
        let auth = Authenticator::from_config(&rpc).unwrap();

        // rpcauth user works.
        assert!(auth.check(Some(&basic("alice", "zecd-test-password"))));
        // The cookie is still generated alongside rpcauth (no user/password pair set).
        let cookie_contents = std::fs::read_to_string(&cookie).unwrap();
        let (cookie_user, cookie_pass) = cookie_contents.split_once(':').unwrap();
        assert_eq!(cookie_user, "__cookie__");
        assert!(auth.check(Some(&basic(cookie_user, cookie_pass))));

        // Malformed entries fail startup.
        let bad = crate::config::RpcConfig {
            auth: vec!["alice-no-colon".to_string()],
            ..rpc
        };
        assert!(Authenticator::from_config(&bad).is_err());
    }
}
