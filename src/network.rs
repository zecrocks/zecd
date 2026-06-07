//! The consensus network a `zecd` instance operates on: mainnet, testnet, or a local
//! regtest chain.
//!
//! librustzcash's own [`zcash_protocol::consensus::Network`] only models main/test, but the
//! whole wallet stack (`WalletDb`, key derivation, address encoding, the sync engine) is
//! generic over [`Parameters`]. [`ZNetwork`] is the single `Parameters` value we thread
//! through that stack so we can add regtest - backed by a [`LocalNetwork`] - without
//! bifurcating every signature.

use anyhow::anyhow;
use zcash_protocol::consensus::{
    BlockHeight, NetworkType, NetworkUpgrade, Parameters, MAIN_NETWORK, TEST_NETWORK,
};
use zcash_protocol::local_consensus::LocalNetwork;

/// The network `zecd` is configured for. `Copy` so it threads by value through the wallet
/// APIs exactly as the upstream `Network` enum did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZNetwork {
    /// Production Zcash.
    Main,
    /// The public testnet.
    Test,
    /// A local regtest chain; activation heights are carried by the inner [`LocalNetwork`].
    Regtest(LocalNetwork),
}

impl ZNetwork {
    /// The short network name used in RPC responses (`getblockchaininfo.chain`) and in
    /// `keys.toml`: `"main"`, `"test"`, or `"regtest"`.
    pub fn name(&self) -> &'static str {
        match self {
            ZNetwork::Main => "main",
            ZNetwork::Test => "test",
            ZNetwork::Regtest(_) => "regtest",
        }
    }

    /// Parse a network name: `main`/`mainnet`, `test`/`testnet`, or `regtest`.
    pub fn parse(s: &str) -> anyhow::Result<ZNetwork> {
        match s.trim() {
            "main" | "mainnet" => Ok(ZNetwork::Main),
            "test" | "testnet" => Ok(ZNetwork::Test),
            "regtest" => Ok(regtest()),
            other => Err(anyhow!("unsupported network: {other}")),
        }
    }
}

impl Parameters for ZNetwork {
    fn network_type(&self) -> NetworkType {
        match self {
            ZNetwork::Main => MAIN_NETWORK.network_type(),
            ZNetwork::Test => TEST_NETWORK.network_type(),
            ZNetwork::Regtest(local) => local.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            ZNetwork::Main => MAIN_NETWORK.activation_height(nu),
            ZNetwork::Test => TEST_NETWORK.activation_height(nu),
            ZNetwork::Regtest(local) => local.activation_height(nu),
        }
    }
}

/// A regtest network with every network upgrade active from height 1 - the `zebra`/`zcashd`
/// regtest convention (and what `deploy/regtest` configures zebra to use). Orchard (NU5) is
/// therefore active for the entire chain.
// `zcash_unstable` is a librustzcash RUSTFLAGS cfg (nu7/zfuture). We don't set it, but the
// gated fields are kept so this literal stays valid if someone builds with those NUs enabled.
#[allow(unexpected_cfgs)]
pub fn regtest() -> ZNetwork {
    let h = Some(BlockHeight::from_u32(1));
    ZNetwork::Regtest(LocalNetwork {
        overwinter: h,
        sapling: h,
        blossom: h,
        heartwood: h,
        canopy: h,
        nu5: h,
        nu6: h,
        nu6_1: h,
        #[cfg(zcash_unstable = "nu7")]
        nu7: h,
        #[cfg(zcash_unstable = "zfuture")]
        z_future: h,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_parse_roundtrip() {
        assert_eq!(ZNetwork::Main.name(), "main");
        assert_eq!(ZNetwork::Test.name(), "test");
        assert_eq!(regtest().name(), "regtest");

        assert_eq!(ZNetwork::parse("mainnet").unwrap(), ZNetwork::Main);
        assert_eq!(ZNetwork::parse(" test ").unwrap(), ZNetwork::Test);
        assert_eq!(ZNetwork::parse("regtest").unwrap(), regtest());
        assert!(ZNetwork::parse("bogus").is_err());
    }

    #[test]
    fn regtest_has_orchard_active_from_genesis() {
        let net = regtest();
        // network_type drives address HRPs / branch IDs.
        assert_eq!(net.network_type(), NetworkType::Regtest);
        // NU5 (Orchard) active at height 1.
        assert!(net.is_nu_active(NetworkUpgrade::Nu5, BlockHeight::from_u32(1)));
    }
}
