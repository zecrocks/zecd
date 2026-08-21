//! Address parsing, validation, and Orchard-receiver checks.
//!
//! `zecd` is Orchard-shielded-only for *receiving* (every `getnewaddress` is a Unified
//! Address exposing only an Orchard receiver). For *sending* we accept any valid recipient
//! address on the configured network; librustzcash's proposal machinery enforces the rest.

use zcash_address::ZcashAddress;
use zcash_keys::address::{Address, UnifiedAddress};
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::PoolType;
use zcash_transparent::address::TransparentAddress;

use crate::coin::Coin;
use crate::error::RpcError;

/// Parse an address string into a network-agnostic [`ZcashAddress`] (for use as a payment
/// recipient). Returns a Bitcoin-Core `RPC_INVALID_ADDRESS_OR_KEY` (-5) on failure.
///
/// `coin` selects the codec and names the currency in the error, so the message is a property
/// of the wallet being paid rather than of this function. Every RPC-boundary caller passes the
/// target wallet's own value rather than hard-coding it.
pub fn parse_recipient(coin: Coin, s: &str) -> Result<ZcashAddress, RpcError> {
    match coin {
        Coin::Zcash => ZcashAddress::try_from_encoded(s).map_err(|_| {
            RpcError::invalid_address_or_key(format!(
                "Invalid {} address: {s}",
                coin.display_name()
            ))
        }),
    }
}

/// Decode an address and verify it belongs to `params`' network. Returns `None` if the
/// string is unparseable or is for a different network.
pub fn decode_on_network<P: Parameters>(params: &P, s: &str) -> Option<Address> {
    Address::decode(params, s)
}

/// Whether a (network-checked) address can receive into the Orchard pool (used by the
/// `FullPrivacy` recipient check).
pub fn has_orchard_receiver(addr: &Address) -> bool {
    addr.can_receive_as(PoolType::ORCHARD)
}

/// Whether a (network-checked) address can receive into any shielded pool (Sapling or Orchard).
/// Used by the `FullPrivacy` per-recipient pre-check: a recipient with no shielded receiver would
/// force a transparent output, which `FullPrivacy` forbids.
pub fn has_shielded_receiver(addr: &Address) -> bool {
    addr.can_receive_as(PoolType::SAPLING) || addr.can_receive_as(PoolType::ORCHARD)
}

/// The pools a (network-checked) address can receive into, in canonical order. For a unified
/// address this enumerates its receivers - so a `u1...` reveals whether it carries transparent,
/// Sapling, and/or Orchard receivers; a bare t-addr is `["transparent"]`, a bare Sapling
/// address `["sapling"]`.
pub fn receiver_types_of(addr: &Address) -> Vec<&'static str> {
    let mut types = Vec::new();
    if addr.can_receive_as(PoolType::Transparent) {
        types.push("transparent");
    }
    if addr.can_receive_as(PoolType::SAPLING) {
        types.push("sapling");
    }
    if addr.can_receive_as(PoolType::ORCHARD) {
        types.push("orchard");
    }
    types
}

/// Reduce a recipient address to the single on-chain receiver a given pool's output actually
/// pays, re-encoded in its own minimal form: a bare transparent or Sapling address, or a
/// single-receiver Unified Address for Orchard (Orchard has no standalone encoding). `pool`
/// is a `v_tx_outputs.output_pool` code (0 = transparent, 2 = Sapling, 3 = Orchard,
/// 4 = Ironwood - which pays the Orchard receiver, so it reduces exactly like 3).
///
/// This is what makes outgoing transaction history deterministic across a restore-from-seed.
/// The full (possibly multi-receiver) UA a caller typed is sender-side metadata that never
/// reaches the chain: it is cached only on the instance that *authored* the send, and a
/// restore-from-seed recovers only the single receiver actually paid (via OVK enhancement).
/// Reducing every outgoing output to that paid receiver yields identical history on the
/// authoring instance and after a restore. It is idempotent: a bare address or an
/// already-single-receiver UA reduces to itself.
///
/// Returns `None` (the caller keeps the recorded string) if the address can't be decoded on
/// `params`' network or carries no receiver for `pool`. Mirrors zallet's
/// `z_listunifiedreceivers` per-receiver re-encoding.
pub fn single_receiver_for_pool<P: Parameters>(params: &P, s: &str, pool: i64) -> Option<String> {
    let addr = decode_on_network(params, s)?;
    match pool {
        // Transparent: a bare t-addr, whether recorded bare or inside a UA.
        0 => match &addr {
            Address::Transparent(t) => Some(t.encode(params)),
            Address::Unified(ua) => ua.transparent().map(|t| t.encode(params)),
            _ => None,
        },
        // Sapling: the bare Sapling receiver.
        2 => match &addr {
            Address::Sapling(p) => Some(p.encode(params)),
            Address::Unified(ua) => ua.sapling().map(|p| p.encode(params)),
            _ => None,
        },
        // Orchard has no standalone encoding, so the single receiver is a UA carrying only it.
        //
        // Ironwood (4) reduces identically and deliberately shares this arm: ironwood notes are
        // received at ordinary Orchard addresses - there is no ironwood receiver typecode - so the
        // receiver an ironwood output pays *is* the Orchard one. Post-NU6.3 this is the common
        // case, not an edge case: an ordinary shielded output is pool 4.
        3 | 4 => match &addr {
            Address::Unified(ua) => ua
                .orchard()
                .and_then(|orch| UnifiedAddress::from_receivers(Some(*orch), None, None))
                .map(|single| single.encode(params)),
            _ => None,
        },
        _ => None,
    }
}

/// Result of `validateaddress`, used to build the JSON response.
pub struct Validation {
    pub is_valid: bool,
    /// Present and `true` when the (valid, on-network) address exposes an Orchard receiver.
    pub is_orchard: bool,
    /// The pools this address can receive into (`transparent`/`sapling`/`orchard`), in
    /// canonical order; for a unified address this enumerates its receivers. Empty if invalid.
    pub receiver_types: Vec<&'static str>,
    /// Hex scriptPubKey for transparent addresses; shielded addresses have no script form.
    pub script_pub_key: Option<String>,
    /// `true` for P2SH transparent addresses, matching bitcoind's `isscript`.
    pub is_script: bool,
}

/// Validate an address against the configured network, reporting validity and whether it
/// can receive Orchard funds.
pub fn validate<P: Parameters>(params: &P, s: &str) -> Validation {
    match decode_on_network(params, s) {
        Some(addr) => {
            let (script_pub_key, is_script) = match &addr {
                Address::Transparent(TransparentAddress::PublicKeyHash(hash)) => {
                    (Some(format!("76a914{}88ac", hex::encode(hash))), false)
                }
                Address::Transparent(TransparentAddress::ScriptHash(hash)) => {
                    (Some(format!("a914{}87", hex::encode(hash))), true)
                }
                _ => (None, false),
            };
            Validation {
                is_valid: true,
                is_orchard: has_orchard_receiver(&addr),
                receiver_types: receiver_types_of(&addr),
                script_pub_key,
                is_script,
            }
        }
        None => Validation {
            is_valid: false,
            is_orchard: false,
            receiver_types: Vec::new(),
            script_pub_key: None,
            is_script: false,
        },
    }
}

/// Verify a recipient parses and is on the configured network, returning the
/// [`ZcashAddress`] for inclusion in a payment.
pub fn parse_recipient_on_network<P: Parameters>(
    coin: Coin,
    params: &P,
    s: &str,
) -> Result<ZcashAddress, RpcError> {
    let zaddr = parse_recipient(coin, s)?;
    if decode_on_network(params, s).is_none() {
        return Err(RpcError::invalid_address_or_key(format!(
            "Address is not valid for the configured network: {s}"
        )));
    }
    Ok(zaddr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ZNetwork;

    // Test vectors shared with zallet's validate_address tests, themselves drawn from
    // zcashd qa/rpc-tests/disablewallet.py and src/wallet/test/rpc_wallet_tests.cpp.
    const MAINNET_P2PKH: &str = "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY";
    const MAINNET_P2SH: &str = "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd";
    const TESTNET_P2PKH: &str = "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86";
    const TESTNET_P2SH: &str = "t3b1jtLvxCstdo1pJs9Tjzc5dmWyvGQSZj8"; // wrong network: this is mainnet-encoded
    const MAINNET_SAPLING: &str =
        "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya";

    #[test]
    fn the_invalid_address_error_names_the_coin() {
        // The message is templated on the coin rather than hardcoded, and for Zcash it renders
        // byte-identically to the string it replaced - the wire contract is unchanged.
        let err = parse_recipient(Coin::Zcash, "not-an-address").unwrap_err();
        assert_eq!(err.message, "Invalid Zcash address: not-an-address");
    }

    #[test]
    fn valid_p2pkh_mainnet_has_p2pkh_script() {
        let v = validate(&ZNetwork::Main, MAINNET_P2PKH);
        assert!(v.is_valid);
        assert!(!v.is_script);
        assert!(!v.is_orchard);
        assert_eq!(v.receiver_types, ["transparent"]);
        let spk = v.script_pub_key.unwrap();
        // OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes
        assert_eq!(spk.len(), 50);
        assert!(spk.starts_with("76a914"));
        assert!(spk.ends_with("88ac"));
    }

    #[test]
    fn valid_p2sh_mainnet_has_p2sh_script() {
        let v = validate(&ZNetwork::Main, MAINNET_P2SH);
        assert!(v.is_valid);
        assert!(v.is_script);
        assert_eq!(v.receiver_types, ["transparent"]);
        let spk = v.script_pub_key.unwrap();
        // OP_HASH160 <20-byte hash> OP_EQUAL = 23 bytes
        assert_eq!(spk.len(), 46);
        assert!(spk.starts_with("a914"));
        assert!(spk.ends_with("87"));
    }

    #[test]
    fn testnet_p2pkh_valid_on_testnet() {
        let v = validate(&ZNetwork::Test, TESTNET_P2PKH);
        assert!(v.is_valid);
        assert!(!v.is_script);
        assert!(v.script_pub_key.unwrap().starts_with("76a914"));
    }

    #[test]
    fn network_mismatch_is_invalid() {
        assert!(!validate(&ZNetwork::Test, MAINNET_P2PKH).is_valid);
        assert!(!validate(&ZNetwork::Test, MAINNET_P2SH).is_valid);
        assert!(!validate(&ZNetwork::Test, TESTNET_P2SH).is_valid);
        assert!(!validate(&ZNetwork::Main, TESTNET_P2PKH).is_valid);
    }

    #[test]
    fn shielded_addresses_have_no_script() {
        let v = validate(&ZNetwork::Main, MAINNET_SAPLING);
        assert!(v.is_valid);
        assert!(v.script_pub_key.is_none());
        assert!(!v.is_script);
        // A bare Sapling address exposes a Sapling receiver but not an Orchard one.
        assert!(!v.is_orchard);
        assert_eq!(v.receiver_types, ["sapling"]);
    }

    // A single-Orchard-receiver testnet UA generated from the checked-in test wallet (see
    // the project docs). It carries only an Orchard receiver.
    const TESTNET_ORCHARD_UA: &str =
        "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0";

    #[test]
    fn single_receiver_is_idempotent_on_bare_and_single_receiver_addresses() {
        // A bare Sapling address reduces to itself for the Sapling pool.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Main, MAINNET_SAPLING, 2).as_deref(),
            Some(MAINNET_SAPLING)
        );
        // A bare transparent address reduces to itself for the transparent pool.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Main, MAINNET_P2PKH, 0).as_deref(),
            Some(MAINNET_P2PKH)
        );
        // A single-Orchard-receiver UA reduces to itself for the Orchard pool.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Test, TESTNET_ORCHARD_UA, 3).as_deref(),
            Some(TESTNET_ORCHARD_UA)
        );
    }

    /// Ironwood (`output_pool` 4) must reduce exactly like Orchard (3).
    ///
    /// Ironwood notes are received at ordinary Orchard addresses - there is no ironwood receiver
    /// typecode - so the single receiver an ironwood output pays *is* the Orchard receiver. While
    /// `single_receiver_for_pool` matched only 0/2/3, code 4 fell through to `None`, and
    /// `wallet_methods::display_address` then fell back to the full recorded `to_address` - the
    /// multi-receiver UA the caller typed, which a restore-from-seed cannot reproduce (it recovers
    /// only the receiver actually paid). That is the restore-determinism guarantee this reduction
    /// exists to provide.
    ///
    /// NB the fallback is not currently observed on outgoing history: `regtest_funded` asserts the
    /// send detail's address differs from the multi-receiver UA, and it passes on an NU6.3-active
    /// chain, so `sent_notes.output_pool` is evidently still 3 for a payment to an Orchard
    /// receiver. This test guards the code path rather than a reproduced user-visible failure -
    /// pool 4 plainly does reach zecd's display layer (`pool_name` maps it to "ironwood"), and if
    /// an outgoing row is ever recorded with it, silently falling back is the wrong answer.
    #[test]
    fn ironwood_reduces_to_the_orchard_receiver() {
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Test, TESTNET_ORCHARD_UA, 4).as_deref(),
            Some(TESTNET_ORCHARD_UA),
            "an ironwood output pays the Orchard receiver, so it reduces like pool 3"
        );
        // And it agrees with Orchard on the same input - the property that makes the authoring
        // node and a restored wallet render identical history.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Test, TESTNET_ORCHARD_UA, 4),
            single_receiver_for_pool(&ZNetwork::Test, TESTNET_ORCHARD_UA, 3),
        );
        // Absent-receiver behaviour matches Orchard too.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Main, MAINNET_SAPLING, 4),
            None
        );
    }

    /// Every pool code `v_tx_outputs.output_pool` can hold must be handled.
    ///
    /// The class of bug this guards is not "ironwood was forgotten here" but "a `match` on a raw
    /// `i64` pool code is not exhaustive, and nothing fails to compile when a pool is added". Three
    /// separate ironwood omissions shipped that way. Enumerate the codes so a fourth pool trips a
    /// test rather than silently taking a fallback path.
    #[test]
    fn every_output_pool_code_is_handled() {
        // A UA carrying every shielded receiver the wallet can be paid at, plus transparent.
        for (code, name) in [
            (0i64, "transparent"),
            (2, "sapling"),
            (3, "orchard"),
            (4, "ironwood"),
        ] {
            // Each code must resolve against an address that carries that receiver. Orchard and
            // ironwood share the Orchard receiver; sapling and transparent have their own.
            let (addr, net) = match code {
                0 => (MAINNET_P2PKH, ZNetwork::Main),
                2 => (MAINNET_SAPLING, ZNetwork::Main),
                _ => (TESTNET_ORCHARD_UA, ZNetwork::Test),
            };
            assert!(
                single_receiver_for_pool(&net, addr, code).is_some(),
                "output_pool code {code} ({name}) is not handled by single_receiver_for_pool; \
                 display_address would fall back to the full recorded address and history would \
                 stop being restore-deterministic for that pool"
            );
        }
    }

    #[test]
    fn single_receiver_returns_none_for_absent_pool() {
        // The Sapling address has no Orchard or transparent receiver.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Main, MAINNET_SAPLING, 3),
            None
        );
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Main, MAINNET_SAPLING, 0),
            None
        );
        // The Orchard-only UA has no Sapling or transparent receiver.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Test, TESTNET_ORCHARD_UA, 2),
            None
        );
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Test, TESTNET_ORCHARD_UA, 0),
            None
        );
        // Undecodable input yields None rather than panicking.
        assert_eq!(
            single_receiver_for_pool(&ZNetwork::Main, "notanaddress", 3),
            None
        );
    }

    #[test]
    fn garbage_inputs_are_invalid() {
        for s in ["", "notanaddress", "t1VydNnkjBzfL1iAMyUbwGKJAF7Pgvu"] {
            let v = validate(&ZNetwork::Main, s);
            assert!(!v.is_valid, "expected {s:?} to be invalid");
            assert!(v.script_pub_key.is_none());
        }
    }
}
