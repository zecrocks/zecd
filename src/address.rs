//! Address parsing, validation, and Orchard-receiver checks.
//!
//! `zecd` is Orchard-shielded-only for *receiving* (every `getnewaddress` is a Unified
//! Address exposing only an Orchard receiver). For *sending* we accept any valid recipient
//! address on the configured network; librustzcash's proposal machinery enforces the rest.

use zcash_address::ZcashAddress;
use zcash_keys::address::Address;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::PoolType;

use crate::error::RpcError;

/// Parse an address string into a network-agnostic [`ZcashAddress`] (for use as a payment
/// recipient). Returns a Bitcoin-Core `RPC_INVALID_ADDRESS_OR_KEY` (-5) on failure.
pub fn parse_recipient(s: &str) -> Result<ZcashAddress, RpcError> {
    ZcashAddress::try_from_encoded(s)
        .map_err(|_| RpcError::invalid_address_or_key(format!("Invalid Zcash address: {s}")))
}

/// Decode an address and verify it belongs to `params`' network. Returns `None` if the
/// string is unparseable or is for a different network.
pub fn decode_on_network<P: Parameters>(params: &P, s: &str) -> Option<Address> {
    Address::decode(params, s)
}

/// Whether a (network-checked) address can receive into the Orchard pool.
pub fn has_orchard_receiver(addr: &Address) -> bool {
    addr.can_receive_as(PoolType::ORCHARD)
}

/// Result of `validateaddress`, used to build the JSON response.
pub struct Validation {
    pub is_valid: bool,
    /// Present and `true` when the (valid, on-network) address exposes an Orchard receiver.
    pub is_orchard: bool,
}

/// Validate an address against the configured network, reporting validity and whether it
/// can receive Orchard funds.
pub fn validate<P: Parameters>(params: &P, s: &str) -> Validation {
    match decode_on_network(params, s) {
        Some(addr) => Validation {
            is_valid: true,
            is_orchard: has_orchard_receiver(&addr),
        },
        None => Validation { is_valid: false, is_orchard: false },
    }
}

/// Verify a recipient parses and is on the configured network, returning the
/// [`ZcashAddress`] for inclusion in a payment.
pub fn parse_recipient_on_network<P: Parameters>(
    params: &P,
    s: &str,
) -> Result<ZcashAddress, RpcError> {
    let zaddr = parse_recipient(s)?;
    if decode_on_network(params, s).is_none() {
        return Err(RpcError::invalid_address_or_key(format!(
            "Address is not valid for the configured network: {s}"
        )));
    }
    Ok(zaddr)
}
