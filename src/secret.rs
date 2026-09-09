//! [`Password`] - a string-shaped secret whose `Debug` never prints the value.
//!
//! Every password zecd holds is configuration: the `[rpc]` credential clients authenticate
//! with, and the `[zebra]` credential zecd authenticates to zebrad with. Both are
//! spend-equivalent (the first lets a client send; the second is only as sensitive as the
//! local node, but it is still a credential), and both ride on types that derive `Debug` and
//! flow through the config resolver, the connection key and the CLI. A bare `String` there is
//! one `debug!(?config)` away from a plaintext password in the log.
//!
//! `Password` is that `String` with the passive-disclosure paths closed: `Debug` renders
//! `<redacted>`, there is no `Display`, and the value comes out only through the explicitly
//! named [`Password::expose`]. It is the same posture as [`crate::hardening`] takes for the
//! seed - make the accidental exposure impossible, rather than relying on nobody writing the
//! log line.
//!
//! This is deliberately not `secrecy::SecretString`: the config types need `PartialEq` (the
//! resolver's round-trip tests compare whole configs), `Deserialize` (the TOML mirrors) and a
//! clap value parser, none of which `secrecy` 0.8 provides.

use std::fmt;
use std::str::FromStr;

use secrecy::Zeroize as _;
use serde::Deserialize;

/// A password read from configuration, the CLI or the environment.
///
/// `Debug` prints `<redacted>` and there is no `Display`, so the value reaches a formatter
/// only via [`expose`](Self::expose). The buffer is zeroized on drop.
#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Password(String);

impl Password {
    /// Wrap a plaintext password.
    pub fn new(value: impl Into<String>) -> Self {
        Password(value.into())
    }

    /// The plaintext, for the one or two places that must actually send or hash it. Named so a
    /// reviewer can grep every site that reaches the secret.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Password::new(value)
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Password::new(value)
    }
}

/// Parsing never fails; this exists so clap can derive a value parser for `Option<Password>`.
impl FromStr for Password {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Password::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_renders_the_secret() {
        let p = Password::new("hunter2");
        assert_eq!(format!("{p:?}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(p.clone())), "Some(<redacted>)");
        // The whole point: a struct that derives Debug cannot leak it either.
        #[derive(Debug)]
        struct Holder {
            password: Option<Password>,
        }
        let holder = Holder { password: Some(p) };
        let rendered = format!("{holder:?}");
        assert!(!rendered.contains("hunter2"), "leaked in {rendered}");
        assert_eq!(
            holder.password.as_ref().map(Password::expose),
            Some("hunter2"),
            "redaction must not change the value itself"
        );
    }

    #[test]
    fn expose_round_trips_and_equality_is_by_value() {
        assert_eq!(Password::new("a").expose(), "a");
        assert_eq!(Password::from("a"), Password::from("a".to_string()));
        assert_ne!(Password::new("a"), Password::new("b"));
        assert_eq!("a".parse::<Password>().expect("infallible").expose(), "a");
    }

    #[test]
    fn deserializes_transparently_from_a_bare_toml_string() {
        #[derive(Deserialize)]
        struct Mirror {
            password: Option<Password>,
        }
        let m: Mirror = toml::from_str("password = \"s3cret\"").expect("parses");
        assert_eq!(m.password.as_ref().map(Password::expose), Some("s3cret"));
    }
}
