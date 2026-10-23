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

    /// The peer protocol version ([ZIP 204]) of the newest network upgrade this build schedules
    /// on this network - the number `getnetworkinfo.protocolversion` reports.
    ///
    /// zecd speaks no P2P, so there is no wire version to report. The useful answer is the one
    /// a node gives: which consensus rules this build follows. Each upgrade's minimum peer
    /// version is that statement in the network's own vocabulary, and a node that has not
    /// reached it is disconnected after activation, so a fixed number goes stale with the next
    /// upgrade. Deriving it from the schedule means a protocol-crate bump that schedules an
    /// upgrade moves this value with it.
    ///
    /// "Schedules", not "has activated": a build carrying a future activation height already
    /// follows those rules from that height, which is what a node's advertised version says
    /// too. The values are zebra's `Version::min_specified_for_upgrade`; testnet and regtest
    /// share testnet's, and from NU7 on mainnet and testnet are assigned distinct versions.
    ///
    /// [ZIP 204]: https://zips.z.cash/zip-0204
    pub fn protocol_version(&self) -> u32 {
        use NetworkUpgrade::*;
        // Newest first; the first one this network schedules decides.
        const NEWEST_FIRST: [NetworkUpgrade; 11] = [
            Nu7, Nu6_3, Nu6_2, Nu6_1, Nu6, Nu5, Canopy, Heartwood, Blossom, Sapling, Overwinter,
        ];
        let mainnet = matches!(self, ZNetwork::Main);
        let Some(newest) = NEWEST_FIRST
            .into_iter()
            .find(|nu| self.activation_height(*nu).is_some())
        else {
            return 170_002;
        };
        let (main, test) = match newest {
            Nu7 => (170_190, 170_180),
            Nu6_3 => (170_160, 170_160),
            Nu6_2 => (170_150, 170_150),
            Nu6_1 => (170_140, 170_130),
            Nu6 => (170_120, 170_110),
            Nu5 => (170_100, 170_050),
            Canopy => (170_013, 170_012),
            Heartwood => (170_011, 170_010),
            Blossom => (170_009, 170_008),
            Sapling => (170_007, 170_007),
            Overwinter => (170_005, 170_003),
        };
        if mainnet {
            main
        } else {
            test
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

/// A regtest network matching the chain the regtest harness runs: NU5 (Orchard) and NU6 active
/// from height 1, then NU6.1/NU6.2 a few blocks in (their activation block needs ZIP-271 lockbox
/// disbursements, so they can't start at genesis). Orchard is active for the entire chain.
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
    // and sets this env var so zecd commits to the matching consensus branch id. The funding
    // wallet is itself a zecd and reads the same variable out of the inherited environment, so
    // all three heights MUST agree (the harness's `NU6_3_ACTIVATION_HEIGHT` is the canonical
    // copy).
    //
    // Unset means no NU6.3 on regtest (a chain built against a zebra without the `"NU6.3"` key).
    // A *set but unparseable* value is fatal rather than silently ignored: falling back to "no
    // NU6.3" would leave zecd committing transactions to the wrong consensus branch id, which
    // surfaces far away as an opaque zebra rejection at broadcast time.
    let nu63 = regtest_height_from_env("ZECD_REGTEST_NU63_HEIGHT", "NU6.3");
    // NU7, from `ZECD_REGTEST_NU7_HEIGHT`, on the same terms as NU6.3 above: compiled
    // unconditionally (the protocol crate exposes it without the old `zcash_unstable = "nu7"`
    // flag), activated on regtest only when asked. Unset - the harness default - keeps the
    // regtest chain at NU6.3, which is also all the pinned funder release understands. Upgrades
    // activate in order, so NU7 needs NU6.3 scheduled strictly below it; anything else would
    // describe a chain no node runs, and zecd would build transactions against it anyway.
    let nu7 = regtest_height_from_env("ZECD_REGTEST_NU7_HEIGHT", "NU7");
    if let Some(nu7) = nu7 {
        match nu63 {
            Some(nu63) if nu63 < nu7 => {}
            _ => panic!(
                "ZECD_REGTEST_NU7_HEIGHT ({nu7}) needs ZECD_REGTEST_NU63_HEIGHT set to a lower \
                 height (got {nu63:?}): network upgrades activate in order"
            ),
        }
    }
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
        nu7,
    })
}

/// A regtest activation height from the environment: `None` when `var` is unset, and a panic
/// naming `var` when it is set to anything but a block height (see the NU6.3 comment in
/// [`regtest`] for why that is fatal rather than ignored).
fn regtest_height_from_env(var: &str, upgrade: &str) -> Option<BlockHeight> {
    let s = std::env::var(var).ok()?;
    Some(BlockHeight::from_u32(
        s.trim().parse::<u32>().unwrap_or_else(|_| {
            panic!(
                "{var} must be a block height (got {s:?}); unset it to build a regtest chain \
                 without {upgrade}"
            )
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::BranchId;

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

    /// NU7 is scheduled on both public networks, at ZIP 259's heights. The height is what lets
    /// zecd build transactions past activation: `BranchId::for_height` picks the NU7 branch id
    /// from it, and a build that lacked it would keep committing to NU6.3 and be rejected by
    /// every upgraded node. Mainnet's height arrived with the `zakura-protocol` 4.0.0 family;
    /// before it, this test pinned mainnet as unscheduled.
    #[test]
    fn nu7_is_scheduled_on_both_networks() {
        for (net, height) in [(ZNetwork::Test, 4_465_026), (ZNetwork::Main, 3_543_405)] {
            let nu7 = net
                .activation_height(NetworkUpgrade::Nu7)
                .expect("the pinned protocol schedules NU7");
            assert_eq!(nu7, BlockHeight::from_u32(height), "{net:?}");
            assert!(
                net.activation_height(NetworkUpgrade::Nu6_3)
                    .is_some_and(|nu63| nu63 < nu7),
                "NU7 must activate after NU6.3 on {net:?}"
            );
            assert_eq!(
                BranchId::for_height(&net, nu7),
                BranchId::Nu7,
                "transactions built at the activation height commit to the NU7 branch id"
            );
            assert_eq!(BranchId::for_height(&net, nu7 - 1), BranchId::Nu6_3);
        }
    }

    /// The reported protocol version follows the newest upgrade this build schedules: NU7 on
    /// both public networks, which ZIP 204 numbers differently (170180 testnet, 170190 mainnet).
    #[test]
    fn protocol_version_follows_the_newest_scheduled_upgrade() {
        assert_eq!(ZNetwork::Test.protocol_version(), 170_180);
        assert_eq!(ZNetwork::Main.protocol_version(), 170_190);

        let h = |n| Some(BlockHeight::from_u32(n));
        let local = |nu6_3, nu7| {
            ZNetwork::Regtest(LocalNetwork {
                overwinter: h(1),
                sapling: h(1),
                blossom: h(1),
                heartwood: h(1),
                canopy: h(1),
                nu5: h(1),
                nu6: h(1),
                nu6_1: h(4),
                nu6_2: h(4),
                nu6_3,
                nu7,
            })
        };
        // Regtest takes testnet's numbers, and an upgrade it does not schedule does not count.
        assert_eq!(local(None, None).protocol_version(), 170_150);
        assert_eq!(local(h(8), None).protocol_version(), 170_160);
        assert_eq!(local(h(8), h(12)).protocol_version(), 170_180);
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
