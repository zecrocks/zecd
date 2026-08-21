//! The currency a `zecd` wallet serves, and the chain it serves it on.
//!
//! [`Coin`] is what the shared layer - config, the wallet registry, dispatch, the address
//! codec - names when it needs to say *which* currency a wallet deals in, so those modules
//! stop hard-coding the answer and stop reaching for `zcash_protocol` to express it. A wallet
//! carries its own value rather than reading a global, which is what lets an error message
//! ("Invalid Zcash address") and a backend token be resolved from the wallet being served.
//!
//! A wallet's concrete chain is derived from (its coin, the daemon's network environment) via
//! [`Coin::chain`], never configured independently: `--testnet`/`--regtest` say "this daemon
//! is a testnet daemon", which makes a mainnet wallet inside a testnet daemon unrepresentable
//! rather than merely rejected.

use crate::network::ZNetwork;

/// The coin a wallet serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Coin {
    /// Zcash.
    Zcash,
}

impl Coin {
    /// Every coin zecd serves, in the order error messages list them.
    pub const SUPPORTED: &'static [Coin] = &[Coin::Zcash];

    /// The lower-case token form: `"zcash"`.
    pub fn name(self) -> &'static str {
        match self {
            Coin::Zcash => "zcash",
        }
    }

    /// The display name used in wire-visible messages, e.g. `"Invalid Zcash address"`.
    pub fn display_name(self) -> &'static str {
        match self {
            Coin::Zcash => "Zcash",
        }
    }

    /// The subdirectory of a **wallet** directory holding this coin's state: `zec` for Zcash,
    /// so a wallet's Zcash data lives under `<datadir>/<wallet>/zec/`
    /// ([`crate::config::coin_dir`]).
    ///
    /// It sits inside the wallet rather than above it because `keys.toml` - the one file in a
    /// wallet directory that is zecd's own - is derived from a BIP-39 seed that serves every
    /// coin at once. One wallet, one seed, one directory per coin underneath it.
    ///
    /// The token is short and coin-specific rather than [`Coin::name`], because it is a path
    /// component operators type and complete - and it is **frozen** once a release ships it:
    /// changing a coin's directory name is a data migration ([`crate::migrate`]), not a rename.
    pub fn data_dir(self) -> &'static str {
        match self {
            Coin::Zcash => "zec",
        }
    }

    /// The subdirectory of [`Coin::data_dir`] holding the wallet-storage **engine**'s own files:
    /// `lrz` (librustzcash) for Zcash, so a Zcash wallet's databases live under
    /// `<datadir>/<wallet>/zec/lrz/` ([`crate::config::engine_dir`]).
    ///
    /// A coin is an engine here, so today this is one directory per coin either way. It is a
    /// level of its own so that everything a *particular* library owns is separable from the
    /// coin's own state: replacing librustzcash - or running a migration between two of its
    /// incompatible schema generations - is then a sibling directory and a rescan, not an
    /// archaeology exercise over a shared one. Nothing zecd owns goes in here; `keys.toml`,
    /// which the seed and the chain cannot rebuild, stays at the wallet root where no engine
    /// swap can reach it.
    ///
    /// Frozen once shipped, exactly like [`Coin::data_dir`].
    pub fn engine_dir(self) -> &'static str {
        match self {
            Coin::Zcash => "lrz",
        }
    }

    /// Parse a token produced by [`Coin::name`]. `None` for anything zecd does not serve.
    pub fn parse(s: &str) -> Option<Coin> {
        Coin::SUPPORTED.iter().copied().find(|c| c.name() == s)
    }

    /// The supported coin tokens, comma-separated, for error messages.
    pub fn supported_names() -> String {
        Coin::SUPPORTED
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// This coin's chain within the daemon's network environment.
    pub fn chain(self, env: ZNetwork) -> CoinNetwork {
        match self {
            Coin::Zcash => CoinNetwork::Zcash(env),
        }
    }
}

/// A wallet's concrete chain: its coin plus the network environment the daemon runs in.
///
/// Derived, never configured. `--testnet`/`--regtest` say "this daemon is a testnet daemon";
/// each wallet's chain follows from (its coin, that environment) via [`Coin::chain`], which
/// is what makes a mainnet wallet inside a testnet daemon unrepresentable rather than merely
/// rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinNetwork {
    /// A Zcash chain (mainnet, testnet, or a local regtest chain).
    Zcash(ZNetwork),
}

impl CoinNetwork {
    /// The coin this chain belongs to.
    pub fn coin(self) -> Coin {
        match self {
            CoinNetwork::Zcash(_) => Coin::Zcash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zcash_is_the_only_supported_coin() {
        assert_eq!(Coin::parse("zcash"), Some(Coin::Zcash));
        assert_eq!(Coin::parse("zzz"), None);
        assert_eq!(Coin::parse("ZCASH"), None, "tokens are case-sensitive");
        assert_eq!(Coin::supported_names(), "zcash");
    }

    #[test]
    fn zcash_chain_derivation_is_identity_for_all_environments() {
        for env in [ZNetwork::Main, ZNetwork::Test, crate::network::regtest()] {
            let chain = Coin::Zcash.chain(env);
            assert_eq!(chain, CoinNetwork::Zcash(env));
            assert_eq!(chain.coin(), Coin::Zcash);
        }
    }

    /// These names are path components every deployment of a release has on disk, so they are
    /// frozen: a change is a migration, not a rename. Pinning them here makes that explicit
    /// rather than leaving it to whoever edits the match arms.
    #[test]
    fn directory_names_are_frozen_and_distinct() {
        assert_eq!(Coin::Zcash.data_dir(), "zec");
        assert_eq!(Coin::Zcash.engine_dir(), "lrz");
        let mut seen = std::collections::BTreeSet::new();
        for coin in Coin::SUPPORTED {
            for dir in [coin.data_dir(), coin.engine_dir()] {
                assert!(
                    !dir.is_empty() && !dir.contains('/') && !dir.starts_with('.'),
                    "{dir:?} must be a plain path component"
                );
            }
            assert!(
                seen.insert(coin.data_dir()),
                "two coins share the data directory {:?}",
                coin.data_dir()
            );
        }
    }

    #[test]
    fn names_round_trip_through_parse() {
        for coin in Coin::SUPPORTED {
            assert_eq!(Coin::parse(coin.name()), Some(*coin));
        }
    }
}
