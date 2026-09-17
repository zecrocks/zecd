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
use crate::pools::{Receiver, ReceiverSet};

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

/// zcashd's `address_type` token for a (network-checked) address, as `z_validateaddress`
/// reports it: `p2pkh`, `p2sh`, `sapling`, `unified`, or `tex`.
///
/// The first four are zcashd's own vocabulary, and the same one `z_getaddressforaccount` takes
/// for its receiver list - note that it calls a transparent receiver `p2pkh`, where zecd's own
/// `receiver_types` extension says `transparent`. `tex` has no zcashd equivalent (ZIP 320
/// postdates it) and is zecd's token.
pub fn address_type_of(addr: &Address) -> &'static str {
    match addr {
        Address::Transparent(TransparentAddress::PublicKeyHash(_)) => "p2pkh",
        Address::Transparent(TransparentAddress::ScriptHash(_)) => "p2sh",
        Address::Sapling(_) => "sapling",
        Address::Unified(_) => "unified",
        Address::Tex(_) => "tex",
    }
}

/// The receivers a (network-checked) address carries, named in zcashd's vocabulary rather than
/// zecd's: `p2pkh` where [`receiver_types_of`] says `transparent`. Kept separate rather than
/// translating at the call site so the two vocabularies stay visibly distinct - they belong to
/// different fields with different audiences, and neither should drift into the other.
pub fn zcashd_receiver_types_of(addr: &Address) -> Vec<&'static str> {
    receiver_types_of(addr)
        .into_iter()
        .map(|t| if t == "transparent" { "p2pkh" } else { t })
        .collect()
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

/// Re-encode one of the wallet's **own** unified addresses to carry exactly the receivers this
/// wallet issues by default (`[pools] default_receivers`): a canonical name for the diversifier
/// index behind it, for the received-by aggregations.
///
/// **Not for transaction history** - that reduces every output, incoming and outgoing alike, to
/// the receiver actually paid ([`single_receiver_for_pool`]), which is an on-chain fact and so
/// cannot move when a config key does. This is the right answer only where the question is
/// "which of my addresses" rather than "what did this output pay":
/// `getreceivedbyaddress`/`listreceivedbyaddress`, which report one row per address and would
/// otherwise split an index across a row per pool. Its config-dependence is acceptable there
/// because that listing enumerates the wallet's *current* addresses.
///
/// The problem it solves: which *encoding* of a diversifier index a payer used never reaches the
/// chain, so a wallet cannot recover it. When the block scan meets a note at an index it has no
/// `addresses` row for - every index on a from-seed restore or after `zecd rescan` -
/// `zcash_client_sqlite`'s `ensure_address` derives one with `UnifiedAddressRequest::ALLOW_ALL`
/// and records *that*, a UA carrying transparent, Sapling and Orchard receivers. zecd issues no
/// such address: `getnewaddress` builds from `default_receivers`, and a transparent receiver is
/// only ever handed out bare. So the recorded string depends on whether `getnewaddress` or the
/// scanner wrote the row first, which made a restored wallet report its receipts under an
/// address the live wallet never returned - and, on a shielded-only wallet, under one carrying a
/// transparent receiver nothing watches.
///
/// Every receiver of a wallet-derived UA sits at one diversifier index, so selecting the subset
/// named by `receivers` yields exactly the address `ufvk.address(index, receivers)` would derive:
/// the same key at the same index produces the same receivers. That makes this a pure
/// receiver-subset operation needing no key material and no derivation, and it is idempotent -
/// an address already carrying exactly `receivers` re-encodes to itself.
///
/// Returns `None`, and the caller keeps the recorded string, when the address is not unified
/// (a bare transparent or Sapling address is its own identity) or when it carries none of
/// `receivers` at all, leaving nothing a unified address could be built from.
pub fn issued_encoding<P: Parameters>(
    params: &P,
    s: &str,
    receivers: &ReceiverSet,
) -> Option<String> {
    let Address::Unified(ua) = decode_on_network(params, s)? else {
        return None;
    };
    // Written out per receiver rather than through a shared closure: the two receiver types are
    // distinct, so one generic helper would have to be a macro to no benefit.
    //
    // This **intersects** rather than requires - a configured receiver the address does not carry
    // is left out, not treated as a failure. That matters because `ALLOW_ALL` allows rather than
    // requires, so at a diversifier index where the Sapling receiver is invalid the recorded
    // address lacks it while a wallet configured for `sapling, orchard` still asks for it.
    // Requiring would abandon the re-encoding there and hand back the recorded string, which is
    // the one shape this function exists to stop reporting: it carries a transparent receiver.
    // Intersecting keeps the narrower shielded address, which is both safe and an address the
    // wallet can receive at. Widening never happens either way - a receiver absent from the
    // input cannot be derived without the viewing key, so a narrower address re-encodes to
    // itself.
    let keep = |r: Receiver| receivers.contains(r);
    let orchard = ua.orchard().filter(|_| keep(Receiver::Orchard)).copied();
    let sapling = ua.sapling().filter(|_| keep(Receiver::Sapling)).copied();
    // The transparent receiver is dropped unconditionally: a `ReceiverSet` is shielded-only, and
    // zecd hands its transparent receivers out bare rather than inside a unified address.
    UnifiedAddress::from_receivers(orchard, sapling, None).map(|ua| ua.encode(params))
}

/// Take a Unified Address apart into its receivers, each re-encoded on its own, keyed by
/// zcashd's `z_listunifiedreceivers` vocabulary (`p2pkh`/`p2sh`/`sapling`/`orchard`). The
/// Orchard receiver has no standalone encoding, so it comes back as a single-receiver Unified
/// Address - the same reduction [`single_receiver_for_pool`] applies to history.
///
/// This is the operation a payment processor needs and could not previously get from zecd:
/// history names each output by the receiver it paid, so matching a history entry back to a
/// multi-receiver address the site handed out means splitting that address into exactly these
/// strings. Pure and key-free - a receiver is a receiver whoever owns it.
pub fn unified_receivers<P: Parameters>(
    params: &P,
    ua: &UnifiedAddress,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let Some(t) = ua.transparent() {
        let kind = match t {
            TransparentAddress::PublicKeyHash(_) => "p2pkh",
            TransparentAddress::ScriptHash(_) => "p2sh",
        };
        out.push((kind, t.encode(params)));
    }
    if let Some(s) = ua.sapling() {
        out.push(("sapling", s.encode(params)));
    }
    if let Some(o) = ua.orchard() {
        if let Some(single) = UnifiedAddress::from_receivers(Some(*o), None, None) {
            out.push(("orchard", single.encode(params)));
        }
    }
    out
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

    /// The committed testnet development mnemonic (valueless TAZ only), used as a fixed key
    /// source so the derivations below are stable.
    const PHRASE: &str = "mechanic vehicle helmet decide plug gorilla frost dial october \
        midnight culture idea mountain fame park social drip bid doctor scatter glance defy \
        moment stage";

    fn test_ufvk() -> zcash_keys::keys::UnifiedFullViewingKey {
        let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(PHRASE).unwrap();
        let seed = mnemonic.to_seed("");
        let account = zip32::AccountId::try_from(0u32).unwrap();
        zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &crate::network::ZNetwork::Test,
            &seed,
            account,
        )
        .expect("derive the test spending key")
        .to_unified_full_viewing_key()
    }

    /// The guarantee the whole re-encoding rests on: dropping the receivers a wallet does not
    /// issue from the scanner's all-receivers address yields **exactly** the address the wallet
    /// would derive at that diversifier index. If it did not, `getreceivedbyaddress` would
    /// canonicalize a query and a stored output to two different strings and report zero.
    ///
    /// Checked against real key derivation rather than a fixture pair, and over several indices,
    /// because the claim is about ZIP 32 (one key at one index produces one set of receivers),
    /// not about one address.
    #[test]
    fn dropping_receivers_reproduces_what_the_wallet_derives_at_that_index() {
        use crate::pools::{Receiver, ReceiverSet};
        use zcash_keys::keys::UnifiedAddressRequest;

        let net = crate::network::ZNetwork::Test;
        let ufvk = test_ufvk();
        let orchard_only = ReceiverSet::single(Receiver::Orchard);
        let both = ReceiverSet::new([Receiver::Sapling, Receiver::Orchard]).unwrap();

        for index in [0u32, 1, 7, 1000, 70_000] {
            let j = zip32::DiversifierIndex::from(index);
            // What `zcash_client_sqlite::wallet::orchard::ensure_address` records when the block
            // scan meets a note at an index with no `addresses` row.
            let Ok(scanned) = ufvk.address(j, UnifiedAddressRequest::ALLOW_ALL) else {
                continue; // not every index is valid for every receiver
            };
            let scanned = scanned.encode(&net);

            for receivers in [&orchard_only, &both] {
                let Ok(issued) = ufvk.address(j, receivers.to_unified_address_request()) else {
                    // This index is not valid for every configured receiver, so the wallet never
                    // issues an address here and `ALLOW_ALL` omitted that receiver too. The
                    // re-encoding intersects, so it still strips the transparent receiver rather
                    // than giving up and handing back the recorded string.
                    let narrowed = issued_encoding(&net, &scanned, receivers)
                        .expect("an intersection still yields a shielded address");
                    let decoded = decode_on_network(&net, &narrowed).expect("decode");
                    assert!(
                        !receiver_types_of(&decoded).contains(&"transparent"),
                        "index {index} re-encoded to something transparent-bearing: {narrowed}"
                    );
                    continue;
                };
                let issued = issued.encode(&net);
                assert_eq!(
                    issued_encoding(&net, &scanned, receivers).as_deref(),
                    Some(issued.as_str()),
                    "index {index}, receivers {}",
                    receivers.display_names()
                );
                // Idempotent: what the wallet issued re-encodes to itself, so a live wallet's
                // recorded addresses pass through this untouched.
                assert_eq!(
                    issued_encoding(&net, &issued, receivers).as_deref(),
                    Some(issued.as_str()),
                    "idempotence at index {index}"
                );
            }
        }
    }

    /// Taking an address apart yields exactly the strings history reports for outputs paid to
    /// it - one per receiver, the Orchard one as a single-receiver UA - so a site can match a
    /// history entry against a stored multi-receiver address by string equality on these.
    #[test]
    fn unified_receivers_are_the_strings_history_reports() {
        use zcash_keys::keys::UnifiedAddressRequest;

        let net = crate::network::ZNetwork::Test;
        let ufvk = test_ufvk();
        let j = zip32::DiversifierIndex::from(0u32);
        let full = ufvk
            .address(j, UnifiedAddressRequest::ALLOW_ALL)
            .expect("derive the all-receivers address");
        let parts: std::collections::BTreeMap<&str, String> =
            unified_receivers(&net, &full).into_iter().collect();
        assert_eq!(
            parts.keys().copied().collect::<Vec<_>>(),
            vec!["orchard", "p2pkh", "sapling"],
            "a three-receiver address yields three parts in zcashd's vocabulary"
        );
        let encoded = full.encode(&net);
        // Each part is what `single_receiver_for_pool` reduces an output in that pool to.
        assert_eq!(
            single_receiver_for_pool(&net, &encoded, 0).as_deref(),
            Some(parts["p2pkh"].as_str())
        );
        assert_eq!(
            single_receiver_for_pool(&net, &encoded, 2).as_deref(),
            Some(parts["sapling"].as_str())
        );
        assert_eq!(
            single_receiver_for_pool(&net, &encoded, 3).as_deref(),
            Some(parts["orchard"].as_str())
        );
        // And a single-receiver address takes apart into itself.
        let orchard_only =
            decode_on_network(&net, &parts["orchard"]).expect("decode the orchard part");
        let Address::Unified(orchard_only) = orchard_only else {
            panic!("the orchard part is a unified address");
        };
        assert_eq!(
            unified_receivers(&net, &orchard_only),
            vec![("orchard", parts["orchard"].clone())]
        );
    }

    /// The scanner's encoding carries a transparent receiver; the re-encoding must drop it. A
    /// shielded-only wallet runs no transparent matcher, so reporting an address that can be
    /// paid transparently would advertise a receiver nothing watches.
    #[test]
    fn the_reencoding_never_keeps_a_transparent_receiver() {
        use crate::pools::{Receiver, ReceiverSet};
        use zcash_keys::keys::UnifiedAddressRequest;

        let net = crate::network::ZNetwork::Test;
        let ufvk = test_ufvk();
        let j = zip32::DiversifierIndex::from(0u32);
        let scanned = ufvk
            .address(j, UnifiedAddressRequest::ALLOW_ALL)
            .expect("derive the all-receivers address");
        assert!(
            scanned.transparent().is_some(),
            "the fixture is only meaningful if the scanner's encoding has a transparent receiver"
        );
        let reencoded = issued_encoding(
            &net,
            &scanned.encode(&net),
            &ReceiverSet::single(Receiver::Orchard),
        )
        .expect("re-encode the scanned address");
        let decoded = decode_on_network(&net, &reencoded).expect("decode the re-encoding");
        assert_eq!(receiver_types_of(&decoded), vec!["orchard"]);
    }

    /// Anything with no unified encoding of its own is left alone, so the caller keeps the
    /// recorded string: a bare transparent address is its own identity in the received-by
    /// aggregations, and a recorded address narrower than the configured set cannot be widened
    /// without the viewing key.
    #[test]
    fn addresses_with_nothing_to_re_encode_are_left_to_the_caller() {
        use crate::pools::{Receiver, ReceiverSet};

        let net = crate::network::ZNetwork::Test;
        let orchard_only = ReceiverSet::single(Receiver::Orchard);
        assert_eq!(
            issued_encoding(&net, "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86", &orchard_only),
            None,
            "a bare transparent address has no unified re-encoding"
        );
        assert_eq!(issued_encoding(&net, "not an address", &orchard_only), None);

        // A recorded address narrower than the configured set is never *widened* - the missing
        // receiver cannot be derived without the viewing key - so it re-encodes to itself.
        let ufvk = test_ufvk();
        let j = zip32::DiversifierIndex::from(0u32);
        let orchard_addr = ufvk
            .address(j, orchard_only.to_unified_address_request())
            .expect("derive the orchard-only address")
            .encode(&net);
        assert_eq!(
            issued_encoding(
                &net,
                &orchard_addr,
                &ReceiverSet::new([Receiver::Sapling, Receiver::Orchard]).unwrap()
            )
            .as_deref(),
            Some(orchard_addr.as_str()),
            "a narrower recorded address re-encodes to itself, never half-derived"
        );
    }

    /// The two receiver vocabularies must stay distinct: zecd's own `receiver_types` extension
    /// says `transparent`, and zcashd's `z_validateaddress` says `p2pkh` for the same receiver.
    #[test]
    fn zcashd_receiver_names_differ_from_zecd_s() {
        let net = crate::network::ZNetwork::Test;
        let taddr = decode_on_network(&net, "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86")
            .expect("decode testnet t-addr");
        assert_eq!(receiver_types_of(&taddr), vec!["transparent"]);
        assert_eq!(zcashd_receiver_types_of(&taddr), vec!["p2pkh"]);
        assert_eq!(address_type_of(&taddr), "p2pkh");
    }
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
