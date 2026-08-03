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

    /// Whether this is a regtest network. Used to gate developer-only RPCs (e.g. `stop`) so
    /// they can't be invoked against a live mainnet/testnet daemon over RPC.
    pub fn is_regtest(&self) -> bool {
        matches!(self, ZNetwork::Regtest(_))
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

/// A regtest network matching the chain the regtest harness runs: NU5 (Orchard) and NU6 active
/// from height 1, then NU6.1/NU6.2 a few blocks in (their activation block needs ZIP-271 lockbox
/// disbursements, so they can't start at genesis). Orchard is active for the entire chain.
// `zcash_unstable` is a librustzcash RUSTFLAGS cfg (nu7/zfuture). We don't set it, but the
// gated fields are kept so this literal stays valid if someone builds with those NUs enabled.
#[allow(unexpected_cfgs)]
pub fn regtest() -> ZNetwork {
    let h = Some(BlockHeight::from_u32(1));
    // NU6.1/NU6.2 activate a few blocks in, not at genesis: NU6.1's activation block must carry
    // ZIP-271 lockbox disbursements, which require a deferred pool that only accrues once NU6 is
    // live. This must match the regtest chain the harness/zebra run (regtest-harness's
    // NU6_2_ACTIVATION_HEIGHT) so zecd commits transactions to the right consensus branch id.
    let nu62 = Some(BlockHeight::from_u32(4));
    // NU6.3 (ironwood) activation height on the regtest chain, from `ZECD_REGTEST_NU63_HEIGHT`.
    // Ironwood is always compiled, so the *code* is unconditional; only the regtest activation
    // height is a knob, because regtest has no protocol-assigned height (real networks get theirs
    // from the pinned protocol crate). The regtest harness configures zebra with NU6.3 at height 8
    // and sets this env var so zecd commits to the matching consensus branch id; the same height
    // goes to the devtool funder via `--activation-heights`. All three MUST agree.
    //
    // Unset means no NU6.3 on regtest (a chain built against a zebra without the `"NU6.3"` key).
    // A *set but unparseable* value is fatal rather than silently ignored: falling back to "no
    // NU6.3" would leave zecd committing transactions to the wrong consensus branch id, which
    // surfaces far away as an opaque zebra rejection at broadcast time.
    let nu63 = match std::env::var("ZECD_REGTEST_NU63_HEIGHT") {
        Ok(s) => Some(BlockHeight::from_u32(
            s.trim().parse::<u32>().unwrap_or_else(|_| {
                panic!(
                    "ZECD_REGTEST_NU63_HEIGHT must be a block height (got {s:?}); \
                     unset it to build a regtest chain without NU6.3"
                )
            }),
        )),
        Err(_) => None,
    };
    ZNetwork::Regtest(LocalNetwork {
        overwinter: h,
        sapling: h,
        blossom: h,
        heartwood: h,
        canopy: h,
        nu5: h,
        nu6: h,
        nu6_1: nu62,
        nu6_2: nu62,
        nu6_3: nu63,
        #[cfg(zcash_unstable = "nu7")]
        nu7: nu62,
        #[cfg(zcash_unstable = "zfuture")]
        z_future: nu62,
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

    /// NU6.3 (ironwood) is live on mainnet and testnet, so the pinned protocol crate must carry an
    /// activation height for both. This is the guard that a dependency bump can't silently drop
    /// ironwood back to "never activates": zecd derives activation purely from these heights
    /// (`is_nu_active(Nu6_3, ..)`), and with no height every mainnet send would keep building
    /// legacy Orchard-V2 output - wrong pool, no error.
    #[test]
    fn nu6_3_is_scheduled_on_mainnet_and_testnet() {
        for net in [ZNetwork::Main, ZNetwork::Test] {
            assert!(
                net.activation_height(NetworkUpgrade::Nu6_3).is_some(),
                "the pinned protocol has no NU6.3 activation height for {}; ironwood cannot \
                 activate there",
                net.name()
            );
        }
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
