//! Estimating what a proposal will serialize to, in bytes.
//!
//! A transaction that is too large to relay is worse than one that is refused: the wallet pays
//! for it in full - selection, witnesses, and minutes of proving - before a node it never sees
//! declines to forward it. So the size a proposal implies is computed at *propose* time, before
//! the prover runs, and [`crate::wallet::actor`] refuses over `[spend] max_tx_bytes` there.
//!
//! **Nothing below the wallet does this.** The Zakura wallet fork carries no proposal size gate
//! (upstream's `Proposal::check_transaction_size` is not in this line), and consensus only
//! bounds a transaction by the block it must fit in - 2 MB, which is far past what any node
//! relays. What actually stops a transaction is node-local relay policy, and that is a fifth of
//! the block limit; see `config::DEFAULT_MAX_TX_BYTES`.
//!
//! # The estimate is an upper bound, and is checked against reality
//!
//! Every term is a fixed field width from [ZIP 225]'s v5 transaction table, and the action
//! counts come from the wallet crate's own `Step::orchard_action_count` /
//! `ironwood_action_count` - the functions the transaction builder itself is driven by - so the
//! estimate cannot silently drift from what gets built. Where a count cannot be derived the
//! estimator rounds *up* (see [`step_shape`]).
//!
//! It is also checked at runtime: every send logs `tx_bytes` beside `est_tx_bytes`, and an
//! estimate that came in under the transaction actually built is a `warn!` naming both. An
//! under-estimate is the one failure mode that matters here - it lets through the transaction
//! this module exists to refuse - so it is loud rather than silent.
//!
//! [ZIP 225]: https://zips.z.cash/zip-0225

use orchard::ValuePool;
use zcash_client_backend::proposal::Step;
use zcash_primitives::transaction::{
    builder::BundlePadding, components::orchard::bundle_version_for_branch,
};
use zcash_protocol::{consensus::BranchId, PoolType};

// ===================== ZIP 225 field widths =====================
//
// Each constant below is one row of the v5 transaction format table, or a sum of adjacent rows
// describing the same object. They are restated here rather than imported because the wallet
// stack exposes only `ACTION_SIZE` (the action description alone, which excludes the spend
// authorization signature and the proof - between them roughly three quarters of what an action
// really costs, so dividing a byte budget by it over-counts what fits by ~3.8x).

/// Bytes per Orchard-family action outside the bundle proof: the action description
/// (`vActionsOrchard`, 820) plus its spend authorization signature
/// (`vSpendAuthSigsOrchard`, 64).
const ORCHARD_ACTION_BYTES: usize = 820 + 64;

/// The constant term of an Orchard-family bundle proof: `sizeProofsOrchard` is
/// `2720 + 2272 * nActionsOrchard`.
const ORCHARD_PROOF_BASE_BYTES: usize = 2720;

/// The per-action term of an Orchard-family bundle proof. See [`ORCHARD_PROOF_BASE_BYTES`].
const ORCHARD_PROOF_PER_ACTION_BYTES: usize = 2272;

/// An Orchard-family bundle's fixed fields: `flagsOrchard` (1), `valueBalanceOrchard` (8),
/// `anchorOrchard` (32), `bindingSigOrchard` (64).
const ORCHARD_BUNDLE_FIXED_BYTES: usize = 1 + 8 + 32 + 64;

/// Bytes per Sapling spend: `vSpendsSapling` (96), `vSpendProofsSapling` (192),
/// `vSpendAuthSigsSapling` (64).
const SAPLING_SPEND_BYTES: usize = 96 + 192 + 64;

/// Bytes per Sapling output: `vOutputsSapling` (756) plus `vOutputProofsSapling` (192).
const SAPLING_OUTPUT_BYTES: usize = 756 + 192;

/// A Sapling bundle's fixed fields: `valueBalanceSapling` (8), `anchorSapling` (32),
/// `bindingSigSapling` (64).
const SAPLING_BUNDLE_FIXED_BYTES: usize = 8 + 32 + 64;

/// Bytes per transparent (P2PKH) input: outpoint (32 + 4), the script-length compact size (1),
/// a `scriptSig` of a DER signature and a compressed public key (1 + 72 + 1 + 33), and
/// `nSequence` (4). A signature is one byte shorter about half the time, so this rounds up.
const TRANSPARENT_INPUT_BYTES: usize = 32 + 4 + 1 + (1 + 72 + 1 + 33) + 4;

/// Bytes per transparent (P2PKH) output: `value` (8), the script-length compact size (1), and
/// the 25-byte `scriptPubKey`.
const TRANSPARENT_OUTPUT_BYTES: usize = 8 + 1 + 25;

/// The v5/v6 transaction header: `header`, `nVersionGroupId`, `nConsensusBranchId`,
/// `lock_time`, `nExpiryHeight`, four bytes each.
const HEADER_BYTES: usize = 4 * 5;

/// Bytes a Bitcoin-style compact size takes to encode `n`.
fn compact_size_bytes(n: usize) -> usize {
    match n {
        0..=252 => 1,
        253..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// The per-pool counts a transaction's serialized size is a function of.
///
/// Deliberately plain counts rather than a proposal reference: the arithmetic that turns them
/// into bytes is the part worth pinning to [ZIP 225], and it is pinned by unit tests that state
/// the counts directly - including against a transaction a node measured for us (see
/// `estimate_matches_the_transaction_zakura_measured`).
///
/// [ZIP 225]: https://zips.z.cash/zip-0225
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxShape {
    /// Actions in the Orchard-pool (V2) bundle, after padding.
    pub orchard_actions: usize,
    /// Actions in the Ironwood-pool (V3) bundle, after padding. Post-NU6.3 a send can carry
    /// both this and an Orchard bundle - each is proved separately, so each costs its own
    /// proof.
    pub ironwood_actions: usize,
    pub sapling_spends: usize,
    pub sapling_outputs: usize,
    pub transparent_inputs: usize,
    pub transparent_outputs: usize,
}

impl TxShape {
    /// Total Orchard-family actions - what `[spend] orchard_action_limit` is expressed in.
    pub fn orchard_family_actions(self) -> usize {
        self.orchard_actions + self.ironwood_actions
    }
}

/// An upper bound on the serialized size, in bytes, of the transaction this shape describes.
pub fn estimate_bytes(shape: TxShape) -> usize {
    let mut bytes = HEADER_BYTES;

    bytes += compact_size_bytes(shape.transparent_inputs)
        + shape.transparent_inputs * TRANSPARENT_INPUT_BYTES
        + compact_size_bytes(shape.transparent_outputs)
        + shape.transparent_outputs * TRANSPARENT_OUTPUT_BYTES;

    bytes += compact_size_bytes(shape.sapling_spends) + compact_size_bytes(shape.sapling_outputs);
    if shape.sapling_spends > 0 || shape.sapling_outputs > 0 {
        bytes += SAPLING_BUNDLE_FIXED_BYTES
            + shape.sapling_spends * SAPLING_SPEND_BYTES
            + shape.sapling_outputs * SAPLING_OUTPUT_BYTES;
    }

    // Each Orchard-protocol pool that has actions is its own bundle, with its own proof: a
    // post-NU6.3 send drawing legacy Orchard notes into Ironwood outputs carries two, and pays
    // both proofs' constant terms.
    for actions in [shape.orchard_actions, shape.ironwood_actions] {
        bytes += compact_size_bytes(actions);
        if actions > 0 {
            let proof = ORCHARD_PROOF_BASE_BYTES + actions * ORCHARD_PROOF_PER_ACTION_BYTES;
            bytes += ORCHARD_BUNDLE_FIXED_BYTES
                + actions * ORCHARD_ACTION_BYTES
                + compact_size_bytes(proof)
                + proof;
        }
    }

    bytes
}

/// The shape of the transaction a proposal step will be built into, at consensus branch
/// `branch`.
///
/// The Orchard-family action counts come from the wallet crate's own
/// `Step::orchard_action_count` / `ironwood_action_count`, called with the padding and bundle
/// version the transaction builder will be configured with - so this counts what the builder
/// builds rather than a second guess at it. Post-NU6.3 that matters: the Orchard pool no longer
/// lets a spend and an output share an action, so its bundle needs `spends + outputs` where the
/// Ironwood bundle beside it needs `max(spends, outputs)`.
///
/// Where a count cannot be derived - the pool has no bundle version at this branch, or the
/// counts are incompatible with the padding - this rounds **up** to `spends + outputs`, the
/// larger of the two rules. An over-estimate costs a refusal that a smaller send gets past; an
/// under-estimate costs a transaction the network drops after it is proved.
pub fn step_shape<NoteRef>(step: &Step<NoteRef>, branch: BranchId) -> TxShape {
    let pool_actions = |pool: PoolType, padding: BundlePadding, value_pool: ValuePool| {
        let spends = step.input_count_in_pool(pool);
        let outputs = step.output_count_in_pool(pool) + step.change_count_in_pool(pool);
        let ceiling = spends + outputs;
        if ceiling == 0 {
            return 0;
        }
        let counted = bundle_version_for_branch(branch, value_pool).and_then(|version| {
            match value_pool {
                ValuePool::Orchard => step.orchard_action_count(padding, version),
                ValuePool::Ironwood => step.ironwood_action_count(padding, version),
            }
            .ok()
        });
        counted.unwrap_or(ceiling)
    };

    TxShape {
        // The Orchard bundle is always padded to the default floor; only the Ironwood bundle's
        // padding varies, and the step records the padding its fee was charged against.
        orchard_actions: pool_actions(
            PoolType::ORCHARD,
            BundlePadding::DEFAULT,
            ValuePool::Orchard,
        ),
        ironwood_actions: pool_actions(
            PoolType::IRONWOOD,
            step.ironwood_bundle_padding(),
            ValuePool::Ironwood,
        ),
        sapling_spends: step.input_count_in_pool(PoolType::SAPLING),
        sapling_outputs: step.output_count_in_pool(PoolType::SAPLING)
            + step.change_count_in_pool(PoolType::SAPLING),
        transparent_inputs: step.input_count_in_pool(PoolType::TRANSPARENT),
        transparent_outputs: step.output_count_in_pool(PoolType::TRANSPARENT)
            + step.change_count_in_pool(PoolType::TRANSPARENT),
    }
}

/// The largest number of Orchard-family actions that fit in `max_bytes`, in a transaction whose
/// only bundle is theirs.
///
/// This is what a *consolidation* wants: `z_mergetoaddress` exists to run repeatedly, so a
/// selection that would not fit should be truncated to one that does rather than refused. A
/// send, which pays what the caller asked or nothing, gets the refusal instead.
///
/// Returns `usize::MAX` when `max_bytes` is 0 (the ceiling disabled), so a caller can `min` with
/// it unconditionally.
pub fn max_orchard_family_actions(max_bytes: usize) -> usize {
    if max_bytes == 0 {
        return usize::MAX;
    }
    // The bundle's own overhead is not linear in the action count (the proof's constant term,
    // the compact sizes), so solve by walking down from the linear over-estimate rather than
    // dividing. At most a couple of iterations: only the compact-size widths step.
    let per_action = ORCHARD_ACTION_BYTES + ORCHARD_PROOF_PER_ACTION_BYTES;
    let mut actions = max_bytes / per_action;
    while actions > 0
        && estimate_bytes(TxShape {
            ironwood_actions: actions,
            ..TxShape::default()
        }) > max_bytes
    {
        actions -= 1;
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anchor for every other assertion here: a real transaction, measured by a real node.
    ///
    /// The extended regtest tier's 200-note `z_mergetoaddress` was refused by zakura with
    /// "transaction is 634056 bytes, exceeding the configured mempool maximum of 250000 bytes"
    /// in every extended zakura run. That transaction is one 200-action Ironwood bundle - 200
    /// notes merged into a single output, on an NU6.3-active chain - so this shape is that
    /// transaction, and the estimate must land on what the node counted.
    ///
    /// If a stack change moves the encoding, this is the test that says so, and the recorded
    /// byte count is the ground truth to re-derive against - not a number to adjust until it
    /// passes.
    #[test]
    fn estimate_matches_the_transaction_zakura_measured() {
        const MEASURED: usize = 634_056;
        let estimate = estimate_bytes(TxShape {
            ironwood_actions: 200,
            ..TxShape::default()
        });
        assert!(
            estimate >= MEASURED,
            "the estimate must be an upper bound: {estimate} < {MEASURED}"
        );
        assert!(
            estimate - MEASURED < MEASURED / 100,
            "estimate {estimate} is more than 1% above the measured {MEASURED}"
        );
    }

    /// Each term restated from the ZIP 225 table, so a mistyped constant fails here rather
    /// than in a node's mempool.
    #[test]
    fn a_single_action_bundle_is_the_sum_of_its_zip_225_fields() {
        let one = estimate_bytes(TxShape {
            ironwood_actions: 1,
            ..TxShape::default()
        });
        let expected = 20      // header, nVersionGroupId, nConsensusBranchId, lock_time, nExpiryHeight
            + 5                // empty counts: tx_in, tx_out, nSpendsSapling, nOutputsSapling, nActionsOrchard
            + 1                // nActionsOrchard for the Ironwood bundle
            + 820              // vActionsOrchard
            + 64               // vSpendAuthSigsOrchard
            + 1 + 8 + 32 + 64  // flagsOrchard, valueBalanceOrchard, anchorOrchard, bindingSigOrchard
            + 3                // sizeProofsOrchard, a compact size over 252
            + (2720 + 2272); // proofsOrchard
        assert_eq!(one, expected);
    }

    /// An empty shape is the header plus one count byte per absent bundle - never a bundle's
    /// fixed fields or a proof, which a transaction without that pool does not carry.
    #[test]
    fn absent_bundles_cost_only_their_count_bytes() {
        assert_eq!(estimate_bytes(TxShape::default()), HEADER_BYTES + 6);
    }

    /// Post-NU6.3 a send can carry both Orchard-protocol bundles, and each is proved
    /// separately: the pair must cost both constant terms, not one shared between them. This is
    /// the case that a single `max(spends, outputs)` action count hides, and it is why the
    /// shape keeps the two pools apart.
    #[test]
    fn two_orchard_protocol_bundles_each_pay_their_own_proof() {
        let split = estimate_bytes(TxShape {
            orchard_actions: 50,
            ironwood_actions: 50,
            ..TxShape::default()
        });
        let single = estimate_bytes(TxShape {
            ironwood_actions: 100,
            ..TxShape::default()
        });
        // At least a whole second proof constant and a second bundle's fixed fields. Stated as
        // a bound rather than an equality: the exact difference also carries a couple of bytes
        // of compact-size width, which is not what this is about.
        assert!(
            split - single >= ORCHARD_PROOF_BASE_BYTES + ORCHARD_BUNDLE_FIXED_BYTES,
            "a second bundle must cost its own proof: {split} - {single}"
        );
    }

    /// The action ceiling is the inverse of the estimate: the count it returns fits, and one
    /// more does not.
    #[test]
    fn the_action_ceiling_is_the_largest_count_that_fits() {
        for max_bytes in [10_000, 100_000, 250_000, 1_000_000] {
            let actions = max_orchard_family_actions(max_bytes);
            let fits = |n| {
                estimate_bytes(TxShape {
                    ironwood_actions: n,
                    ..TxShape::default()
                }) <= max_bytes
            };
            assert!(fits(actions), "{actions} actions should fit in {max_bytes}");
            assert!(
                !fits(actions + 1),
                "{} actions should not fit in {max_bytes}",
                actions + 1
            );
        }
    }

    /// The relay ceiling this exists to respect holds far fewer actions than the shipped
    /// `orchard_action_limit` would suggest, which is the whole reason a byte gate is needed
    /// beside the action cap: 50 actions fit comfortably, 200 do not.
    #[test]
    fn the_default_relay_ceiling_holds_between_the_default_cap_and_the_merge_limit() {
        let actions = max_orchard_family_actions(crate::config::DEFAULT_MAX_TX_BYTES);
        assert!(
            (crate::config::DEFAULT_ORCHARD_ACTION_LIMIT..200).contains(&actions),
            "expected the ceiling to sit between the action cap and the merge limit, got \
             {actions}"
        );
    }

    /// A disabled ceiling never truncates a selection.
    #[test]
    fn a_disabled_ceiling_admits_any_action_count() {
        assert_eq!(max_orchard_family_actions(0), usize::MAX);
    }

    #[test]
    fn compact_size_widths_step_at_the_encoding_boundaries() {
        assert_eq!(compact_size_bytes(0), 1);
        assert_eq!(compact_size_bytes(252), 1);
        assert_eq!(compact_size_bytes(253), 3);
        assert_eq!(compact_size_bytes(0xFFFF), 3);
        assert_eq!(compact_size_bytes(0x1_0000), 5);
    }
}
