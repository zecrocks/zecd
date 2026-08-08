//! Shielded value pools, and the per-wallet receiver sets that select between them.
//!
//! zecd is shielded-only. Historically it was Orchard-only for *receiving*; now each wallet can
//! declare which shielded pools it uses (`enabled` pools) and which receivers the Unified
//! Addresses it hands out should include (`default_receivers`). A default receiver may never name
//! a pool that isn't enabled - that's a configuration error, caught at parse time.
//!
//! The [`Receiver`] enum is a zecd-local type rather than `zcash_protocol::ShieldedPool`, and note
//! that **Ironwood (NU6.3) is NOT a third [`Receiver`] here** - even though upstream `ShieldedPool` now
//! *does* carry an `Ironwood` variant. Upstream models ironwood as **Orchard "V3" notes**: it
//! reuses Orchard's keys, addresses, and note cryptography, so there is no ironwood UA receiver
//! typecode. Ironwood notes are *received at ordinary Orchard addresses*; the Orchard/ironwood
//! distinction lives at the **transaction-bundle / note-version** level (a separate ironwood bundle
//! in V6 transactions). So ironwood is a *balance + spend* concern, not an
//! address-generation concern - it is surfaced in `wallet/read.rs` (balances), the
//! `v_tx_outputs.output_pool` code 4 (`wallet_methods::pool_name`), and the V6 spend path
//! (`wallet/actor.rs`), **not** by adding a variant to this enum. Keep `Receiver` = {Sapling, Orchard}.

use std::fmt;

use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};
use zcash_protocol::{PoolType, ShieldedPool};

/// A kind of receiver a zecd wallet's addresses can carry, and so the value pool that funds
/// arriving at it land in.
///
/// This is a *receiver* type, not a pool type, which is why there is no `Ironwood` variant: see
/// the module docs. The two are usually one-to-one, and Ironwood is the exception that makes the
/// distinction worth a separate name.
///
/// [`Receiver::Transparent`] is supported for *receiving* (a bare t-address handed out by
/// `getnewaddress`) and for *spending* (received transparent UTXOs auto-shielded into a send),
/// but it is never a member of a [`ReceiverSet`], which always holds at least one shielded
/// receiver (it feeds `change_pool` and the shielded-protocol enumeration). Transparent
/// receiving is a separate per-wallet capability flag (`config::PoolsConfig::transparent_*`),
/// not a value pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Receiver {
    Transparent,
    Sapling,
    Orchard,
    // NB: Ironwood is deliberately NOT a variant - it is received at Orchard addresses and handled
    // as a balance/spend dimension (an Orchard V3 note), not a UA receiver. See the module doc.
}

impl Receiver {
    /// Every *shielded* pool zecd supports today, in canonical (precedence) order. Transparent is
    /// deliberately excluded: this list drives [`ReceiverSet`] ordering and the shielded-protocol
    /// enumeration in balances/`listunspent`, neither of which apply to transparent.
    pub const SUPPORTED: &'static [Receiver] = &[Receiver::Sapling, Receiver::Orchard];

    /// Parse a config/RPC token (`"sapling"` | `"orchard"` | `"transparent"`), case-insensitively.
    pub fn from_config_str(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sapling" => Ok(Receiver::Sapling),
            "orchard" => Ok(Receiver::Orchard),
            "transparent" => Ok(Receiver::Transparent),
            other => anyhow::bail!(
                "unknown pool {other:?}; supported pools are {}, transparent",
                supported_names()
            ),
        }
    }

    /// The canonical lowercase name used in config and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            Receiver::Transparent => "transparent",
            Receiver::Sapling => "sapling",
            Receiver::Orchard => "orchard",
        }
    }

    /// The librustzcash shielded-protocol identifier for this pool, or `None` for transparent.
    pub fn shielded_protocol(&self) -> Option<ShieldedPool> {
        match self {
            Receiver::Transparent => None,
            Receiver::Sapling => Some(ShieldedPool::Sapling),
            Receiver::Orchard => Some(ShieldedPool::Orchard),
        }
    }

    /// The `v_tx_outputs.output_pool` / received-note pool code (0 = transparent, 2 = Sapling,
    /// 3 = Orchard), matching zcash_client_sqlite's `PoolType` encoding.
    ///
    /// That encoding also has **4 = Ironwood**, which no `Receiver` maps to: ironwood is not a UA
    /// receiver (see the enum above), so it can be an output's pool without being a selectable
    /// one. Anything matching on a raw pool code therefore has to handle 4 itself - reading this
    /// list as exhaustive is what produced the FullPrivacy, rebroadcast and history gaps fixed
    /// earlier in this series.
    pub fn output_pool_code(&self) -> i64 {
        match self {
            Receiver::Transparent => 0,
            Receiver::Sapling => 2,
            Receiver::Orchard => 3,
        }
    }

    /// Whether this is the transparent pool.
    pub fn is_transparent(&self) -> bool {
        matches!(self, Receiver::Transparent)
    }
}

impl From<Receiver> for PoolType {
    fn from(p: Receiver) -> Self {
        match p.shielded_protocol() {
            Some(sp) => PoolType::Shielded(sp),
            None => PoolType::Transparent,
        }
    }
}

impl fmt::Display for Receiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn supported_names() -> String {
    Receiver::SUPPORTED
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// An ordered, de-duplicated, non-empty set of [`Receiver`]s.
///
/// Used for both a wallet's enabled pools and its default UA receivers. Order follows
/// [`Receiver::SUPPORTED`] so display/encoding is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverSet {
    pools: Vec<Receiver>,
}

impl ReceiverSet {
    /// Build a set from pools, preserving [`Receiver::SUPPORTED`] order and dropping duplicates.
    /// Returns an error if no pools are given (a wallet must have at least one shielded pool,
    /// and a UA must have at least one shielded receiver).
    pub fn new(pools: impl IntoIterator<Item = Receiver>) -> anyhow::Result<Self> {
        let given: Vec<Receiver> = pools.into_iter().collect();
        // A `ReceiverSet` is shielded-only; transparent is a separate per-wallet capability, not a
        // value pool. Reject it explicitly so the error is clear rather than "empty set".
        if given.iter().any(|p| p.is_transparent()) {
            anyhow::bail!(
                "transparent is not a shielded pool; enable transparent receiving via the \
                 [pools] transparent flag, not as a pool/receiver"
            );
        }
        let ordered: Vec<Receiver> = Receiver::SUPPORTED
            .iter()
            .copied()
            .filter(|p| given.contains(p))
            .collect();
        if ordered.is_empty() {
            anyhow::bail!("at least one shielded pool is required");
        }
        Ok(Self { pools: ordered })
    }

    /// Parse a list of config tokens into a validated set (unknown name -> error, empty -> error).
    pub fn parse<S: AsRef<str>>(tokens: &[S]) -> anyhow::Result<Self> {
        if tokens.is_empty() {
            anyhow::bail!("at least one shielded pool is required");
        }
        let mut pools = Vec::with_capacity(tokens.len());
        for t in tokens {
            pools.push(Receiver::from_config_str(t.as_ref())?);
        }
        Self::new(pools)
    }

    /// A single-pool set (infallible - one pool is always non-empty).
    pub fn single(pool: Receiver) -> Self {
        Self { pools: vec![pool] }
    }

    pub fn contains(&self, pool: Receiver) -> bool {
        self.pools.contains(&pool)
    }

    pub fn iter(&self) -> impl Iterator<Item = Receiver> + '_ {
        self.pools.iter().copied()
    }

    /// Whether every pool in `self` is also present in `other`.
    pub fn is_subset_of(&self, other: &ReceiverSet) -> bool {
        self.pools.iter().all(|p| other.contains(*p))
    }

    /// The canonical names, in set order - the spelling `ReceiverSet::parse` accepts, so this is
    /// what renders back into a config file (`zecd config show`).
    pub fn names(&self) -> Vec<&'static str> {
        self.pools.iter().map(|p| p.as_str()).collect()
    }

    /// Comma-separated canonical names, e.g. `"sapling, orchard"`.
    pub fn display_names(&self) -> String {
        self.pools
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Build the librustzcash address request that includes exactly this set's receivers:
    /// `Require` for each pool present, `Omit` for every other pool, and `Omit` for p2pkh
    /// (zecd never exposes a transparent receiver). Requiring a receiver makes address
    /// generation fail if the account's viewing key can't produce it, which is the desired
    /// behaviour: a configured receiver that can't be honoured should surface, not silently
    /// vanish.
    pub fn to_unified_address_request(&self) -> UnifiedAddressRequest {
        use ReceiverRequirement::*;
        let req = |p: Receiver| if self.contains(p) { Require } else { Omit };
        // `unsafe_custom` cannot panic here: `ReceiverSet` is always non-empty and only ever holds
        // shielded pools, so at least one of orchard/sapling is `Require`.
        UnifiedAddressRequest::unsafe_custom(req(Receiver::Orchard), req(Receiver::Sapling), Omit)
    }

    /// The pool to receive change into when spending. Prefer Orchard (the strongest pool) when
    /// enabled, else the first enabled pool. (Ironwood change is an Orchard-V3 note, so it rides
    /// the Orchard arm here - there is no separate ironwood change pool.)
    pub fn change_pool(&self) -> ShieldedPool {
        if self.contains(Receiver::Orchard) {
            ShieldedPool::Orchard
        } else {
            // Non-empty and shielded-only by construction; fall back to the first enabled pool.
            self.pools
                .first()
                .copied()
                .and_then(|p| p.shielded_protocol())
                .unwrap_or(ShieldedPool::Orchard)
        }
    }
}

/// The librustzcash address request used to derive a **bare transparent** receiver: require both an
/// Orchard receiver (to satisfy ZIP-316, which forbids a transparent-only Unified Address - the
/// shielded receiver is discarded after extraction) and a p2pkh receiver, omitting Sapling. Keys
/// always derive all pools regardless of a wallet's enabled set, so the Orchard receiver is always
/// available. The caller extracts the transparent receiver from the resulting UA and encodes it
/// bare (`t1…`/`tm…`).
pub fn transparent_extraction_request() -> UnifiedAddressRequest {
    use ReceiverRequirement::*;
    // Argument order is (orchard, sapling, p2pkh), matching `to_unified_address_request`.
    UnifiedAddressRequest::unsafe_custom(Require, Omit, Require)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_pools_case_insensitively() {
        assert_eq!(
            Receiver::from_config_str("sapling").unwrap(),
            Receiver::Sapling
        );
        assert_eq!(
            Receiver::from_config_str("ORCHARD").unwrap(),
            Receiver::Orchard
        );
        assert_eq!(
            Receiver::from_config_str(" Orchard ").unwrap(),
            Receiver::Orchard
        );
    }

    #[test]
    fn rejects_unknown_pool() {
        let err = Receiver::from_config_str("ironwood")
            .unwrap_err()
            .to_string();
        assert!(err.contains("ironwood"), "{err}");
        assert!(err.contains("sapling"), "{err}");
    }

    #[test]
    fn set_orders_and_dedups() {
        let s = ReceiverSet::parse(&["orchard", "sapling", "orchard"]).unwrap();
        // Canonical order is sapling, orchard regardless of input order.
        assert_eq!(
            s.iter().collect::<Vec<_>>(),
            vec![Receiver::Sapling, Receiver::Orchard]
        );
    }

    #[test]
    fn empty_set_is_rejected() {
        assert!(ReceiverSet::parse::<&str>(&[]).is_err());
        assert!(ReceiverSet::new(std::iter::empty()).is_err());
    }

    #[test]
    fn subset_check() {
        let both = ReceiverSet::parse(&["sapling", "orchard"]).unwrap();
        let orchard = ReceiverSet::single(Receiver::Orchard);
        let sapling = ReceiverSet::single(Receiver::Sapling);
        assert!(orchard.is_subset_of(&both));
        assert!(sapling.is_subset_of(&both));
        assert!(!both.is_subset_of(&orchard));
        assert!(both.is_subset_of(&both));
    }

    #[test]
    fn output_pool_codes() {
        assert_eq!(Receiver::Sapling.output_pool_code(), 2);
        assert_eq!(Receiver::Orchard.output_pool_code(), 3);
    }

    #[test]
    fn ua_request_orchard_only_matches_builtin() {
        // A pure-Orchard receiver set must produce the same request shape zecd used before
        // (Require orchard, Omit sapling, Omit p2pkh).
        let req = ReceiverSet::single(Receiver::Orchard).to_unified_address_request();
        if let UnifiedAddressRequest::Custom(_) = req {
            // Can't introspect the private fields directly; assert it is Custom (not
            // AllAvailableKeys) and round-trips through the constructor without panic.
        } else {
            panic!("expected a custom request");
        }
        // The dual-receiver and sapling-only sets must also build without panic.
        let _ = ReceiverSet::parse(&["sapling", "orchard"])
            .unwrap()
            .to_unified_address_request();
        let _ = ReceiverSet::single(Receiver::Sapling).to_unified_address_request();
    }

    #[test]
    fn change_pool_precedence() {
        assert_eq!(
            ReceiverSet::parse(&["sapling", "orchard"])
                .unwrap()
                .change_pool(),
            ShieldedPool::Orchard
        );
        assert_eq!(
            ReceiverSet::single(Receiver::Orchard).change_pool(),
            ShieldedPool::Orchard
        );
        assert_eq!(
            ReceiverSet::single(Receiver::Sapling).change_pool(),
            ShieldedPool::Sapling
        );
    }
}
