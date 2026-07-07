//! Shielded value pools and the configurable per-wallet pool/receiver sets.
//!
//! zecd is shielded-only. Historically it was Orchard-only for *receiving*; now each wallet can
//! declare which shielded pools it uses (`enabled` pools) and which receivers the Unified
//! Addresses it hands out should include (`default_receivers`). A default receiver may never name
//! a pool that isn't enabled - that's a configuration error, caught at parse time.
//!
//! The [`Pool`] enum is a zecd-local type rather than `zcash_protocol::ShieldedPool`, and note
//! that **Ironwood (NU6.3) is NOT a third [`Pool`] here** - even though upstream `ShieldedPool` now
//! *does* carry an `Ironwood` variant. Upstream models ironwood as **Orchard "V3" notes**: it
//! reuses Orchard's keys, addresses, and note cryptography, so there is no ironwood UA receiver
//! typecode. Ironwood notes are *received at ordinary Orchard addresses*; the Orchard/ironwood
//! distinction lives at the **transaction-bundle / note-version** level (a separate ironwood bundle
//! in V6 transactions). So ironwood is a *balance + spend* concern, not an
//! address-generation/receiver concern - it is surfaced in `wallet/read.rs` (balances), the
//! `v_tx_outputs.output_pool` code 4 (`wallet_methods::pool_name`), and the V6 spend path
//! (`wallet/actor.rs`), **not** by adding a variant to this enum. Keep `Pool` = {Sapling, Orchard}.

use std::fmt;

use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};
use zcash_protocol::{PoolType, ShieldedPool};

/// A value pool that a zecd wallet can receive into and spend from.
///
/// [`Pool::Transparent`] is supported for *receiving* (a bare t-address handed out by
/// `getnewaddress`) and for *spending* (received transparent UTXOs auto-shielded into a send),
/// but it is never a member of a [`PoolSet`] - a `PoolSet` is always "≥1 shielded pool" (it feeds
/// `change_pool` and the shielded-protocol enumeration). Transparent receiving is a separate
/// per-wallet capability flag (`config::PoolsConfig::transparent_*`), not a value pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pool {
    Transparent,
    Sapling,
    Orchard,
    // NB: Ironwood is deliberately NOT a variant - it is received at Orchard addresses and handled
    // as a balance/spend dimension (an Orchard V3 note), not a UA receiver. See the module doc.
}

impl Pool {
    /// Every *shielded* pool zecd supports today, in canonical (precedence) order. Transparent is
    /// deliberately excluded: this list drives [`PoolSet`] ordering and the shielded-protocol
    /// enumeration in balances/`listunspent`, neither of which apply to transparent.
    pub const SUPPORTED: &'static [Pool] = &[Pool::Sapling, Pool::Orchard];

    /// Parse a config/RPC token (`"sapling"` | `"orchard"` | `"transparent"`), case-insensitively.
    pub fn from_config_str(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sapling" => Ok(Pool::Sapling),
            "orchard" => Ok(Pool::Orchard),
            "transparent" => Ok(Pool::Transparent),
            other => anyhow::bail!(
                "unknown pool {other:?}; supported pools are {}, transparent",
                supported_names()
            ),
        }
    }

    /// The canonical lowercase name used in config and RPC.
    pub fn as_str(&self) -> &'static str {
        match self {
            Pool::Transparent => "transparent",
            Pool::Sapling => "sapling",
            Pool::Orchard => "orchard",
        }
    }

    /// The librustzcash shielded-protocol identifier for this pool, or `None` for transparent.
    pub fn shielded_protocol(&self) -> Option<ShieldedPool> {
        match self {
            Pool::Transparent => None,
            Pool::Sapling => Some(ShieldedPool::Sapling),
            Pool::Orchard => Some(ShieldedPool::Orchard),
        }
    }

    /// The `v_tx_outputs.output_pool` / received-note pool code (0 = transparent, 2 = Sapling,
    /// 3 = Orchard), matching zcash_client_sqlite's `PoolType` encoding.
    pub fn output_pool_code(&self) -> i64 {
        match self {
            Pool::Transparent => 0,
            Pool::Sapling => 2,
            Pool::Orchard => 3,
        }
    }

    /// Whether this is the transparent pool.
    pub fn is_transparent(&self) -> bool {
        matches!(self, Pool::Transparent)
    }
}

impl From<Pool> for PoolType {
    fn from(p: Pool) -> Self {
        match p.shielded_protocol() {
            Some(sp) => PoolType::Shielded(sp),
            None => PoolType::Transparent,
        }
    }
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn supported_names() -> String {
    Pool::SUPPORTED
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// An ordered, de-duplicated, non-empty set of [`Pool`]s.
///
/// Used for both a wallet's enabled pools and its default UA receivers. Order follows
/// [`Pool::SUPPORTED`] so display/encoding is deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSet {
    pools: Vec<Pool>,
}

impl PoolSet {
    /// Build a set from pools, preserving [`Pool::SUPPORTED`] order and dropping duplicates.
    /// Returns an error if no pools are given (a wallet must have at least one shielded pool,
    /// and a UA must have at least one shielded receiver).
    pub fn new(pools: impl IntoIterator<Item = Pool>) -> anyhow::Result<Self> {
        let given: Vec<Pool> = pools.into_iter().collect();
        // A `PoolSet` is shielded-only; transparent is a separate per-wallet capability, not a
        // value pool. Reject it explicitly so the error is clear rather than "empty set".
        if given.iter().any(|p| p.is_transparent()) {
            anyhow::bail!(
                "transparent is not a shielded pool; enable transparent receiving via the \
                 [pools] transparent flag, not as a pool/receiver"
            );
        }
        let ordered: Vec<Pool> = Pool::SUPPORTED
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
            pools.push(Pool::from_config_str(t.as_ref())?);
        }
        Self::new(pools)
    }

    /// A single-pool set (infallible - one pool is always non-empty).
    pub fn single(pool: Pool) -> Self {
        Self { pools: vec![pool] }
    }

    pub fn contains(&self, pool: Pool) -> bool {
        self.pools.contains(&pool)
    }

    pub fn iter(&self) -> impl Iterator<Item = Pool> + '_ {
        self.pools.iter().copied()
    }

    /// Whether every pool in `self` is also present in `other`.
    pub fn is_subset_of(&self, other: &PoolSet) -> bool {
        self.pools.iter().all(|p| other.contains(*p))
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
        let req = |p: Pool| if self.contains(p) { Require } else { Omit };
        // `unsafe_custom` cannot panic here: `PoolSet` is always non-empty and only ever holds
        // shielded pools, so at least one of orchard/sapling is `Require`.
        UnifiedAddressRequest::unsafe_custom(req(Pool::Orchard), req(Pool::Sapling), Omit)
    }

    /// The pool to receive change into when spending. Prefer Orchard (the strongest pool) when
    /// enabled, else the first enabled pool. (Ironwood change is an Orchard-V3 note, so it rides
    /// the Orchard arm here - there is no separate ironwood change pool.)
    pub fn change_pool(&self) -> ShieldedPool {
        if self.contains(Pool::Orchard) {
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
        assert_eq!(Pool::from_config_str("sapling").unwrap(), Pool::Sapling);
        assert_eq!(Pool::from_config_str("ORCHARD").unwrap(), Pool::Orchard);
        assert_eq!(Pool::from_config_str(" Orchard ").unwrap(), Pool::Orchard);
    }

    #[test]
    fn rejects_unknown_pool() {
        let err = Pool::from_config_str("ironwood").unwrap_err().to_string();
        assert!(err.contains("ironwood"), "{err}");
        assert!(err.contains("sapling"), "{err}");
    }

    #[test]
    fn set_orders_and_dedups() {
        let s = PoolSet::parse(&["orchard", "sapling", "orchard"]).unwrap();
        // Canonical order is sapling, orchard regardless of input order.
        assert_eq!(
            s.iter().collect::<Vec<_>>(),
            vec![Pool::Sapling, Pool::Orchard]
        );
    }

    #[test]
    fn empty_set_is_rejected() {
        assert!(PoolSet::parse::<&str>(&[]).is_err());
        assert!(PoolSet::new(std::iter::empty()).is_err());
    }

    #[test]
    fn subset_check() {
        let both = PoolSet::parse(&["sapling", "orchard"]).unwrap();
        let orchard = PoolSet::single(Pool::Orchard);
        let sapling = PoolSet::single(Pool::Sapling);
        assert!(orchard.is_subset_of(&both));
        assert!(sapling.is_subset_of(&both));
        assert!(!both.is_subset_of(&orchard));
        assert!(both.is_subset_of(&both));
    }

    #[test]
    fn output_pool_codes() {
        assert_eq!(Pool::Sapling.output_pool_code(), 2);
        assert_eq!(Pool::Orchard.output_pool_code(), 3);
    }

    #[test]
    fn ua_request_orchard_only_matches_builtin() {
        // A pure-Orchard receiver set must produce the same request shape zecd used before
        // (Require orchard, Omit sapling, Omit p2pkh).
        let req = PoolSet::single(Pool::Orchard).to_unified_address_request();
        if let UnifiedAddressRequest::Custom(_) = req {
            // Can't introspect the private fields directly; assert it is Custom (not
            // AllAvailableKeys) and round-trips through the constructor without panic.
        } else {
            panic!("expected a custom request");
        }
        // The dual-receiver and sapling-only sets must also build without panic.
        let _ = PoolSet::parse(&["sapling", "orchard"])
            .unwrap()
            .to_unified_address_request();
        let _ = PoolSet::single(Pool::Sapling).to_unified_address_request();
    }

    #[test]
    fn change_pool_precedence() {
        assert_eq!(
            PoolSet::parse(&["sapling", "orchard"])
                .unwrap()
                .change_pool(),
            ShieldedPool::Orchard
        );
        assert_eq!(
            PoolSet::single(Pool::Orchard).change_pool(),
            ShieldedPool::Orchard
        );
        assert_eq!(
            PoolSet::single(Pool::Sapling).change_pool(),
            ShieldedPool::Sapling
        );
    }
}
